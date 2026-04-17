#!/usr/bin/env python3
"""Tesla BLE daemon — manages BLE connection to a Tesla vehicle using VCSEC and Infotainment protocols."""
import asyncio
import hashlib
import logging
import os
import re
import struct
import time

from bleak import BleakClient, BleakScanner

import cereal.messaging as messaging
from openpilot.system.teslable.crypto import (
  load_or_create_key, ecdh_shared_key, encrypt_gcm, encrypt_gcm_personalized,
  decrypt_gcm, derive_subkey, key_id,
)
from openpilot.system.teslable.proto import encode_field, decode_fields, get_field

TESLA_VIN_PATH = "/data/tesla/vin"
TESLA_KEY_PATH = "/data/tesla/key.pem"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("teslad")

# Tesla BLE UUIDs
TESLA_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"
TESLA_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"
TESLA_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"

TESLA_BLE_NAME_RE = re.compile(r"^S[0-9a-f]{16}C$")

SCAN_DURATION = 5.0
SCAN_INTERVAL = 10.0

DOMAIN_VEHICLE_SECURITY = 2
DOMAIN_INFOTAINMENT = 3

# ── RKE actions ──

RKE_ACTION_UNLOCK = 0
RKE_ACTION_LOCK = 1
RKE_ACTION_OPEN_TRUNK = 2
RKE_ACTION_OPEN_FRUNK = 3
RKE_ACTION_OPEN_CHARGE_PORT = 4
RKE_ACTION_CLOSE_CHARGE_PORT = 5
RKE_ACTION_CANCEL_EXTERNAL_AUTHENTICATE = 6
RKE_ACTION_SINGLE_PRESS_TOP = 7
RKE_ACTION_DOUBLE_PRESS_TOP = 8
RKE_ACTION_TRIPLE_PRESS_TOP = 9
RKE_ACTION_HOLD_TOP = 10
RKE_ACTION_SINGLE_PRESS_BACK = 11
RKE_ACTION_DOUBLE_PRESS_BACK = 12
RKE_ACTION_TRIPLE_PRESS_BACK = 13
RKE_ACTION_HOLD_BACK = 14
RKE_ACTION_SINGLE_PRESS_FRONT = 15
RKE_ACTION_DOUBLE_PRESS_FRONT = 16
RKE_ACTION_TRIPLE_PRESS_FRONT = 17
RKE_ACTION_HOLD_FRONT = 18
RKE_ACTION_REMOTE_DRIVE = 20
RKE_ACTION_SINGLE_PRESS_LEFT = 21
RKE_ACTION_DOUBLE_PRESS_LEFT = 22
RKE_ACTION_TRIPLE_PRESS_LEFT = 23
RKE_ACTION_HOLD_LEFT = 24
RKE_ACTION_SINGLE_PRESS_RIGHT = 25
RKE_ACTION_DOUBLE_PRESS_RIGHT = 26
RKE_ACTION_TRIPLE_PRESS_RIGHT = 27
RKE_ACTION_HOLD_RIGHT = 28
RKE_ACTION_AUTO_SECURE_VEHICLE = 29
RKE_ACTION_WAKE_VEHICLE = 30

# ── Closure move types ──

CLOSURE_MOVE_NONE = 0
CLOSURE_MOVE_MOVE = 1
CLOSURE_MOVE_STOP = 2
CLOSURE_MOVE_OPEN = 3
CLOSURE_MOVE_CLOSE = 4


def ble_frame(msg):
  return struct.pack('>H', len(msg)) + msg


def make_reassembler(rx_queue):
  """Reassemble fragmented BLE notifications using the 2-byte length prefix.
  Puts complete messages (without the length prefix) into rx_queue."""
  buffer = bytearray()
  expected = [None]  # nonlocal-as-list so closure can mutate

  def on_notify(_handle, data):
    buffer.extend(bytes(data))
    while True:
      if expected[0] is None:
        if len(buffer) < 2:
          return
        expected[0] = int.from_bytes(buffer[:2], 'big')
      if len(buffer) < 2 + expected[0]:
        return
      message = bytes(buffer[2:2 + expected[0]])
      del buffer[:2 + expected[0]]
      expected[0] = None
      rx_queue.put_nowait(message)

  return on_notify


# ── VCSEC message builders ──

def build_ephemeral_key_request(kid_bytes):
  key_id_msg = encode_field(1, kid_bytes)
  info_req = encode_field(1, 3) + encode_field(2, key_id_msg)
  unsigned_msg = encode_field(1, info_req)
  return encode_field(2, unsigned_msg)


def build_get_status_request():
  # InformationRequest { informationRequestType = GET_STATUS (0) }
  info_req = encode_field(1, 0)
  unsigned_msg = encode_field(1, info_req)
  return encode_field(2, unsigned_msg)


def build_whitelist_request(public_key_bytes):
  # PermissionChange { key=PublicKey, keyRole=OWNER(2) }
  # KeyMetadata { keyFormFactor=CLOUD_KEY(9) }
  # WhitelistOperation { addKeyToWhitelistAndAddPermissions (field 5) = perm_change,
  #                      metadataForKey (field 6) = metadata }
  pubkey_msg = encode_field(1, public_key_bytes)
  perm_change = encode_field(1, pubkey_msg) + encode_field(4, 2)  # OWNER
  metadata = encode_field(1, 9)                                    # CLOUD_KEY
  whitelist_op = encode_field(5, perm_change) + encode_field(6, metadata)
  unsigned_msg = encode_field(16, whitelist_op)
  signed_msg = encode_field(2, unsigned_msg) + encode_field(3, 2)
  return encode_field(1, signed_msg)


def build_signed_command(shared_key, kid_bytes, counter, unsigned_msg_bytes):
  plaintext = encode_field(2, unsigned_msg_bytes)
  ciphertext, tag = encrypt_gcm(shared_key, counter, plaintext)
  signed_msg = b''
  signed_msg += encode_field(2, ciphertext)
  signed_msg += encode_field(3, 0)         # SIGNATURE_TYPE_AES_GCM
  signed_msg += encode_field(4, tag)       # signature
  signed_msg += encode_field(5, kid_bytes) # keyId
  signed_msg += encode_field(6, counter)   # counter
  return encode_field(1, signed_msg)


def build_rke_action(action):
  return encode_field(2, action)


def build_closure_move(front_driver=0, front_passenger=0, rear_driver=0, rear_passenger=0,
                       rear_trunk=0, front_trunk=0, charge_port=0, tonneau=0):
  msg = b''
  if front_driver: msg += encode_field(1, front_driver)
  if front_passenger: msg += encode_field(2, front_passenger)
  if rear_driver: msg += encode_field(3, rear_driver)
  if rear_passenger: msg += encode_field(4, rear_passenger)
  if rear_trunk: msg += encode_field(5, rear_trunk)
  if front_trunk: msg += encode_field(6, front_trunk)
  if charge_port: msg += encode_field(7, charge_port)
  if tonneau: msg += encode_field(8, tonneau)
  return encode_field(4, msg)


# ── Response parser ──

def parse_from_vcsec(data):
  fields = decode_fields(data)
  result = {}

  session_info_bytes = get_field(fields, 2)
  if session_info_bytes is not None:
    si = decode_fields(session_info_bytes)
    result['session_info'] = {
      'token': get_field(si, 1),
      'counter': get_field(si, 2),
      'public_key': get_field(si, 3),
    }

  command_status_bytes = get_field(fields, 4)
  if command_status_bytes is not None:
    cs = decode_fields(command_status_bytes)
    result['command_status'] = {
      'operation_status': get_field(cs, 1),
    }

  vehicle_status_bytes = get_field(fields, 1)
  if vehicle_status_bytes is not None:
    vs = decode_fields(vehicle_status_bytes)
    closures = {}
    closure_bytes = get_field(vs, 1)
    if closure_bytes is not None:
      cs = decode_fields(closure_bytes)
      for idx, name in enumerate([
        'frontDriverDoor', 'frontPassengerDoor', 'rearDriverDoor', 'rearPassengerDoor',
        'rearTrunk', 'frontTrunk', 'chargePort', 'tonneau',
      ], start=1):
        closures[name] = get_field(cs, idx)
    result['vehicle_status'] = {
      'vehicle_lock_state': get_field(vs, 2),
      'vehicle_sleep_status': get_field(vs, 3),
      'user_presence': get_field(vs, 4),
      'closures': closures,
    }

  return result


# ── Infotainment (RoutableMessage) builders ──

def _bits_to_float(bits):
  """Reinterpret a uint32 bit pattern (how decode_fields returns wire-type-5 values) as float32."""
  if bits is None:
    return None
  return struct.unpack('<f', struct.pack('<I', bits))[0]


CHARGING_STATE_NAMES = {
  1: "Unknown", 2: "Disconnected", 3: "NoPower", 4: "Starting",
  5: "Charging", 6: "Complete", 7: "Stopped", 8: "Calibrating",
}
SHIFT_STATE_NAMES = {1: "Invalid", 2: "P", 3: "R", 4: "N", 5: "D", 6: "SNA"}


def _parse_oneof_void(submsg_bytes, names):
  """A Tesla oneof-of-Void gets wire-encoded as the presence of a single length-delimited
  field at the chosen field-number (with empty body). Return its name, or None."""
  if not submsg_bytes:
    return None
  for fn, _, _ in decode_fields(submsg_bytes):
    if fn in names:
      return names[fn]
  return None


def parse_vehicle_data(plaintext, car_state):
  """Decode carserver.Response { vehicleData: VehicleData } into car_state dict."""
  if not plaintext:
    return
  fields = decode_fields(plaintext)
  vd_bytes = get_field(fields, 2)
  if not vd_bytes:
    return
  vf = decode_fields(vd_bytes)

  def _sub(field_num):
    b = get_field(vf, field_num)
    return decode_fields(b) if b else None

  # charge_state (field 3)
  cs = _sub(3)
  if cs:
    state = _parse_oneof_void(get_field(cs, 1), CHARGING_STATE_NAMES)
    if state is not None:
      car_state['chargingState'] = state
    if (v := get_field(cs, 114)) is not None: car_state['chargePercent'] = float(v)
    if (v := get_field(cs, 111)) is not None: car_state['batteryRangeMiles'] = _bits_to_float(v)
    if (v := get_field(cs, 104)) is not None: car_state['chargeLimitSoc'] = int(v)
    if (v := get_field(cs, 122)) is not None: car_state['chargerPower'] = float(v)

  # climate_state (field 4)
  cc = _sub(4)
  if cc:
    if (v := get_field(cc, 101)) is not None: car_state['insideTempC'] = _bits_to_float(v)
    if (v := get_field(cc, 102)) is not None: car_state['outsideTempC'] = _bits_to_float(v)
    if (v := get_field(cc, 103)) is not None: car_state['driverTempSetpointC'] = _bits_to_float(v)
    if (v := get_field(cc, 104)) is not None: car_state['passengerTempSetpointC'] = _bits_to_float(v)
    if (v := get_field(cc, 110)) is not None: car_state['hvacOn'] = bool(v)

  # drive_state (field 5)
  dc = _sub(5)
  if dc:
    shift = _parse_oneof_void(get_field(dc, 1), SHIFT_STATE_NAMES)
    if shift is not None:
      car_state['gear'] = shift
    if (v := get_field(dc, 106)) is not None: car_state['speedMph'] = _bits_to_float(v)
    elif (v := get_field(dc, 102)) is not None: car_state['speedMph'] = float(v)
    if (v := get_field(dc, 105)) is not None: car_state['odometerMiles'] = int(v) / 100.0

  # location_state (field 8)
  lc = _sub(8)
  if lc:
    if (v := get_field(lc, 101)) is not None: car_state['latitude'] = _bits_to_float(v)
    if (v := get_field(lc, 102)) is not None: car_state['longitude'] = _bits_to_float(v)
    if (v := get_field(lc, 103)) is not None: car_state['heading'] = float(v)

  # media_state (field 20)
  mc = _sub(20)
  if mc:
    if (v := get_field(mc, 3)) is not None:
      car_state['mediaArtist'] = v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
    if (v := get_field(mc, 4)) is not None:
      car_state['mediaTrack'] = v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
    # media_playback_status is an enum varint: 0=Stopped, 1=Playing, 2=Paused
    if (v := get_field(mc, 9)) is not None:
      car_state['mediaPlaying'] = int(v) == 1


def build_response_aad(vin, domain, counter, flags, request_id, fault):
  """Build AAD for AES-GCM Response decryption (per Tesla responseMetadata())."""
  tlv = b''
  tlv += bytes([0, 1, 9])                                 # TAG_SIGNATURE_TYPE = AES_GCM_RESPONSE (9)
  tlv += bytes([1, 1, domain])                            # TAG_DOMAIN
  vin_bytes = vin.encode()
  tlv += bytes([2, len(vin_bytes)]) + vin_bytes           # TAG_PERSONALIZATION
  tlv += bytes([5, 4]) + counter.to_bytes(4, 'big')       # TAG_COUNTER
  tlv += bytes([7, 4]) + flags.to_bytes(4, 'big')         # TAG_FLAGS (always included for responses)
  tlv += bytes([8, len(request_id)]) + request_id         # TAG_REQUEST_HASH
  tlv += bytes([9, 4]) + fault.to_bytes(4, 'big')         # TAG_FAULT
  tlv += bytes([0xFF])                                     # TAG_END
  return hashlib.sha256(tlv).digest()


def build_metadata_aad(vin, epoch, expires_at, counter, flags=0):
  """Build TLV metadata and return its SHA-256 hash for use as AES-GCM AAD."""
  tlv = b''
  tlv += bytes([0, 1, 5])                                  # TAG_SIGNATURE_TYPE = AES_GCM_PERSONALIZED (5)
  tlv += bytes([1, 1, DOMAIN_INFOTAINMENT])                 # TAG_DOMAIN = 3
  vin_bytes = vin.encode()
  tlv += bytes([2, len(vin_bytes)]) + vin_bytes             # TAG_PERSONALIZATION = VIN
  tlv += bytes([3, len(epoch)]) + epoch                     # TAG_EPOCH
  tlv += bytes([4, 4]) + expires_at.to_bytes(4, 'big')      # TAG_EXPIRES_AT
  tlv += bytes([5, 4]) + counter.to_bytes(4, 'big')         # TAG_COUNTER
  if flags:
    tlv += bytes([7, 4]) + flags.to_bytes(4, 'big')         # TAG_FLAGS
  tlv += bytes([0xFF])                                       # TAG_END
  return hashlib.sha256(tlv).digest()


def build_session_info_request(public_key_bytes, domain, routing_address):
  """Build RoutableMessage with SessionInfoRequest for a domain."""
  uuid = os.urandom(16)
  session_info_req = encode_field(1, public_key_bytes)
  to_dest = encode_field(1, domain)
  from_dest = encode_field(2, routing_address)
  msg = b''
  msg += encode_field(6, to_dest)
  msg += encode_field(7, from_dest)
  msg += encode_field(14, session_info_req)
  msg += encode_field(51, uuid)
  return msg, uuid


def parse_routable_response(data):
  """Parse a RoutableMessage response."""
  fields = decode_fields(data)
  result = {}

  session_info_bytes = get_field(fields, 15)
  if session_info_bytes is not None:
    si = decode_fields(session_info_bytes)
    result['session_info'] = {
      'counter': get_field(si, 1),
      'public_key': get_field(si, 2),
      'epoch': get_field(si, 3),
      'clock_time': get_field(si, 4),
      'status': get_field(si, 5),
    }

  payload = get_field(fields, 10)
  if payload is not None:
    result['payload'] = payload

  status = get_field(fields, 12)
  if status is not None:
    sf = decode_fields(status)
    result['message_status'] = {
      'operation_status': get_field(sf, 1),
      'fault': get_field(sf, 2),
    }

  # Tesla's response uses field 50 for request_uuid (not 52 as in the proto)
  request_uuid = get_field(fields, 50)
  if request_uuid is not None:
    result['request_uuid'] = request_uuid

  # signature_data (field 13) carries AES_GCM_Response_Signature_Data (sub-field 9) for encrypted responses
  sig_data = get_field(fields, 13)
  if sig_data is not None:
    sd = decode_fields(sig_data)
    gcm_resp = get_field(sd, 9)
    if gcm_resp is not None:
      gr = decode_fields(gcm_resp)
      result['response_sig'] = {
        'nonce': get_field(gr, 1),
        'counter': get_field(gr, 2),
        'tag': get_field(gr, 3),
      }

  flags = get_field(fields, 52)
  if flags is not None:
    result['flags'] = flags

  return result


FLAG_ENCRYPT_RESPONSE = 1 << 1   # bit 1 (FLAG_ENCRYPT_RESPONSE enum = 1 → value = 2)


def build_infotainment_command(aes_key, public_key_bytes, routing_address, vin,
                                epoch, counter, expires_at, action_bytes,
                                flags=FLAG_ENCRYPT_RESPONSE):
  """Build a signed RoutableMessage for an infotainment command."""
  nonce = os.urandom(12)
  aad = build_metadata_aad(vin, epoch, expires_at, counter, flags=flags)
  ciphertext, tag = encrypt_gcm_personalized(aes_key, nonce, action_bytes, aad)

  # AES_GCM_Personalized_Signature_Data
  sig_data = b''
  sig_data += encode_field(1, epoch)
  sig_data += encode_field(2, nonce)
  sig_data += encode_field(3, counter)
  # field 4 expires_at is fixed32 (wire type 5): tag byte + 4 LE bytes, no length prefix
  sig_data += bytes([(4 << 3) | 5]) + struct.pack('<I', expires_at)
  sig_data += encode_field(5, tag)

  # SignatureData { signer_identity (1), AES_GCM_Personalized_data (5) }
  signer = encode_field(1, public_key_bytes)  # KeyIdentity.public_key
  signature_data = encode_field(1, signer) + encode_field(5, sig_data)

  to_dest = encode_field(1, DOMAIN_INFOTAINMENT)
  from_dest = encode_field(2, routing_address)
  uuid = os.urandom(16)

  msg = b''
  msg += encode_field(6, to_dest)
  msg += encode_field(7, from_dest)
  msg += encode_field(10, ciphertext)   # encrypted payload
  msg += encode_field(13, signature_data)
  msg += encode_field(51, uuid)
  if flags:
    msg += encode_field(52, flags)
  return msg, uuid, tag


# ── Infotainment action builders (carserver.Action > VehicleAction) ──

def build_vehicle_action(field_number, action_body=b''):
  """Build Action { vehicleAction (field 2) { <field_number>: action_body } }"""
  vehicle_action = encode_field(field_number, action_body) if action_body else encode_field(field_number, b'')
  return encode_field(2, vehicle_action)


def action_honk_horn():
  return build_vehicle_action(27)

def action_flash_lights():
  return build_vehicle_action(26)

def action_hvac_auto(on=True):
  # HvacAutoAction { power_on (field 1) = bool }
  return build_vehicle_action(10, encode_field(1, 1 if on else 0))

def action_hvac_steering_wheel_heater(on=True):
  # HvacSteeringWheelHeaterAction { power_on (field 1) = bool }
  return build_vehicle_action(13, encode_field(1, 1 if on else 0))

def action_media_toggle_playback():
  return build_vehicle_action(15)

def action_media_next_track():
  return build_vehicle_action(19)

def action_media_previous_track():
  return build_vehicle_action(20)

def action_media_volume(volume_delta=0, volume_abs=-1):
  # MediaUpdateVolume { media_volume_delta (field 1) = float }
  body = b''
  if volume_abs >= 0:
    body += _encode_float(4, volume_abs)  # absolute volume
  else:
    body += _encode_float(1, volume_delta)
  return build_vehicle_action(16, body)

def action_sentry_mode(on=True):
  # VehicleControlSetSentryModeAction { on (field 1) = bool }
  return build_vehicle_action(30, encode_field(1, 1 if on else 0))

def action_trigger_homelink():
  return build_vehicle_action(33)

def action_window(vent=False, close=False):
  # VehicleControlWindowAction: oneof { unknown=2, vent=3, close=4 } all Void
  body = b''
  if vent:
    body += encode_field(3, b'')
  elif close:
    body += encode_field(4, b'')
  return build_vehicle_action(34, body)

# HvacSeatHeaterAction oneofs are Void fields:
# seat_heater_level: UNKNOWN=1, OFF=2, LOW=3, MED=4, HIGH=5
# seat_position: UNKNOWN=6, FL=7, FR=8, RL=9, RL_BACK=10, R_CENTER=11, RR=12, RR_BACK=13, 3L=14, 3R=15
SEAT_HEATER_LEVELS = {'off': 2, 'low': 3, 'med': 4, 'high': 5}
SEAT_POSITIONS = {
  'fl': 7, 'fr': 8, 'rl': 9, 'rc': 11, 'rr': 12,
  'driver': 7, 'passenger': 8,
}

def action_seat_heater(seat, level):
  # HvacSeatHeaterActions { hvacSeatHeaterAction (field 1, repeated) { level Void, seat Void } }
  inner = encode_field(level, b'') + encode_field(seat, b'')
  return build_vehicle_action(36, encode_field(1, inner))

def action_charging_start():
  return build_vehicle_action(6, encode_field(1, 1))  # start

def action_charging_stop():
  return build_vehicle_action(6, encode_field(1, 2))  # stop

def action_set_charge_limit(percent):
  return build_vehicle_action(5, encode_field(1, percent))

def action_ping():
  return build_vehicle_action(46)


# GetVehicleData substate field numbers (inside GetVehicleData at VehicleAction field 1)
GET_VEHICLE_DATA_KINDS = {
  'charge':    2,  # getChargeState
  'climate':   3,  # getClimateState
  'drive':     4,  # getDriveState
  'location':  7,  # getLocationState
  'closures':  8,  # getClosuresState
  'tires':     14, # getTirePressureState
  'media':     15, # getMediaState
  'media_detail': 16,
  'software':  17,
}


def action_get_vehicle_data(kinds):
  """kinds: iterable of field numbers selecting which substates to fetch."""
  body = b''
  for k in sorted(set(kinds)):
    body += encode_field(k, b'')  # Void inside GetVehicleData
  return build_vehicle_action(1, body)

def action_bioweapon_mode(on=True):
  return build_vehicle_action(35, encode_field(1, 1 if on else 0))

def action_set_vehicle_name(name):
  return build_vehicle_action(54, encode_field(1, name.encode()))

def _encode_float(field_number, value):
  """Encode a proto float (fixed32, wire type 5): tag byte + 4 LE bytes."""
  return bytes([(field_number << 3) | 5]) + struct.pack('<f', value)


def action_hvac_temp(driver_temp=None, passenger_temp=None):
  # HvacTemperatureAdjustmentAction: driver_temp_celsius=6, passenger_temp_celsius=7.
  # If only one value is given, mirror it to both zones (otherwise the unset zone
  # defaults to 0/LO). Field 3 absolute_celsius exists but doesn't behave as a target set.
  if driver_temp is not None and passenger_temp is None:
    passenger_temp = driver_temp
  body = b''
  if driver_temp is not None:
    body += _encode_float(6, driver_temp)
  if passenger_temp is not None:
    body += _encode_float(7, passenger_temp)
  return build_vehicle_action(14, body)


# ── Tesla session ──

class TeslaSession:
  def __init__(self, client, rx_queue, private_key, public_key_bytes, kid_bytes,
               vin=None, routing_address=None):
    self.client = client
    self.rx_queue = rx_queue
    self.private_key = private_key
    self.public_key_bytes = public_key_bytes
    self.kid = kid_bytes
    self.vin = vin
    self.routing_address = routing_address or os.urandom(16)

    # session state (populated by negotiate_*/whitelist)
    self.shared_key = None
    self.counter = int(time.monotonic())
    self.whitelisted = False
    self.infotainment_key = None
    self.infotainment_epoch = None
    self.infotainment_clock_time = None      # vehicle's session clock at negotiation
    self.infotainment_clock_anchor = None    # our monotonic time at that moment
    self.infotainment_counter = int(time.monotonic())

    # accumulated car state (VCSEC VehicleStatus broadcasts + infotainment query responses)
    self.car_state = {}
    # most recent decrypted infotainment Response plaintext (carserver.Response bytes)
    self.last_response_plaintext = None

  def _update_from_vcsec(self, parsed):
    """If parsed FromVCSECMessage has a vehicle_status, fold it into car_state. Returns True if updated."""
    vs = parsed.get('vehicle_status') if parsed else None
    if not vs:
      return False
    self.car_state['lockState'] = vs.get('vehicle_lock_state') or 0
    self.car_state['sleepStatus'] = vs.get('vehicle_sleep_status') or 0
    self.car_state['userPresence'] = vs.get('user_presence') or 0
    for name, val in (vs.get('closures') or {}).items():
      if val is not None:
        self.car_state[name] = val
    self.car_state['vcsecUpdatedAt'] = time.monotonic()
    return True

  @property
  def infotainment_ready(self):
    return self.infotainment_key is not None

  async def _drain_rx(self):
    await asyncio.sleep(0.5)
    while not self.rx_queue.empty():
      self.rx_queue.get_nowait()

  async def negotiate_vcsec(self):
    """Send ephemeral key request. Sets self.whitelisted and self.shared_key."""
    await self._drain_rx()
    msg = build_ephemeral_key_request(self.kid)
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))
    try:
      response = await asyncio.wait_for(self.rx_queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
      log.error("no response to ephemeral key request")
      return False
    parsed = parse_from_vcsec(response)
    vehicle_pubkey = parsed.get('session_info', {}).get('public_key') if 'session_info' in parsed else None
    if vehicle_pubkey is None:
      log.warning("key not on whitelist — run whitelist command")
      self.whitelisted = False
      return False
    self.shared_key = ecdh_shared_key(self.private_key, vehicle_pubkey)
    self.whitelisted = True
    log.info("VCSEC session established")
    return True

  async def negotiate_infotainment(self):
    """Establish infotainment session. Requires VCSEC session + VIN."""
    if not self.whitelisted or self.vin is None:
      return False
    await self._drain_rx()
    msg, _uuid = build_session_info_request(self.public_key_bytes, DOMAIN_INFOTAINMENT, self.routing_address)
    log.info("requesting infotainment session...")
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))
    info_response = None
    for _ in range(10):
      try:
        response = await asyncio.wait_for(self.rx_queue.get(), timeout=3.0)
        parsed = parse_routable_response(response)
        log.info(f"infotainment rx: {parsed}")
        if 'session_info' in parsed:
          info_response = parsed
          break
      except asyncio.TimeoutError:
        break
    if info_response is None:
      log.warning("no infotainment session response")
      return False
    si = info_response['session_info']
    if si.get('public_key') and si.get('epoch'):
      # AES-GCM-personalized uses the raw ECDH-derived 16-byte key directly.
      # (The "authenticated command" subkey is for HMAC-personalized, not AES-GCM.)
      self.infotainment_key = ecdh_shared_key(self.private_key, si['public_key'])
      self.infotainment_epoch = si['epoch']
      self.infotainment_clock_time = si.get('clock_time', 0)
      self.infotainment_clock_anchor = time.monotonic()
      log.info("infotainment session established")
      return True
    log.warning(f"infotainment session incomplete: {si}")
    return False

  async def request_status(self):
    """Send VCSEC GET_STATUS; car replies with a VehicleStatus broadcast."""
    log.info("requesting VCSEC status...")
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(build_get_status_request()))
    deadline = asyncio.get_event_loop().time() + 3.0
    while asyncio.get_event_loop().time() < deadline:
      try:
        response = await asyncio.wait_for(self.rx_queue.get(), timeout=1.0)
        if self._update_from_vcsec(parse_from_vcsec(response)):
          return "ok"
      except asyncio.TimeoutError:
        break
    return "timeout"

  async def whitelist(self):
    """Send whitelist request; wait up to 60s for NFC card tap on center console."""
    log.info(">>> TAP NFC KEY CARD ON CENTER CONSOLE <<<")
    await self._drain_rx()
    wl_msg = build_whitelist_request(self.public_key_bytes)
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(wl_msg))
    deadline = asyncio.get_event_loop().time() + 60
    while asyncio.get_event_loop().time() < deadline:
      try:
        response = await asyncio.wait_for(self.rx_queue.get(), timeout=2.0)
        fields = decode_fields(response)
        if 4 in [f[0] for f in fields]:
          log.info("whitelist accepted!")
          return True
      except asyncio.TimeoutError:
        continue
    log.warning("whitelist timed out — card not tapped in 60s")
    return False

  async def send_rke(self, action):
    cmd = build_signed_command(self.shared_key, self.kid, self.counter, build_rke_action(action))
    self.counter += 1
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(cmd))

  async def send_closure_move(self, **kwargs):
    cmd = build_signed_command(self.shared_key, self.kid, self.counter, build_closure_move(**kwargs))
    self.counter += 1
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(cmd))

  async def wait_for_response(self, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
      try:
        response = await asyncio.wait_for(self.rx_queue.get(), timeout=2.0)
        parsed = parse_from_vcsec(response)
        self._update_from_vcsec(parsed)
        if parsed.get('command_status') is not None:
          status = parsed['command_status'].get('operation_status')
          return "ok" if status in (None, 0) else f"status={status}"
      except asyncio.TimeoutError:
        break
    return "timeout"

  # ── Door lock/unlock ──

  async def unlock(self):
    log.info("unlocking...")
    await self.send_rke(RKE_ACTION_UNLOCK)
    return await self.wait_for_response()

  async def lock(self):
    log.info("locking...")
    await self.send_rke(RKE_ACTION_LOCK)
    return await self.wait_for_response()

  # ── Trunk ──

  async def open_trunk(self):
    log.info("opening trunk...")
    await self.send_rke(RKE_ACTION_OPEN_TRUNK)
    return await self.wait_for_response()

  async def close_trunk(self):
    log.info("closing trunk...")
    await self.send_closure_move(rear_trunk=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  # ── Frunk ──

  async def open_frunk(self):
    log.info("opening frunk...")
    await self.send_rke(RKE_ACTION_OPEN_FRUNK)
    return await self.wait_for_response()

  # ── Charge port ──

  async def open_charge_port(self):
    log.info("opening charge port...")
    await self.send_rke(RKE_ACTION_OPEN_CHARGE_PORT)
    return await self.wait_for_response()

  async def close_charge_port(self):
    log.info("closing charge port...")
    await self.send_rke(RKE_ACTION_CLOSE_CHARGE_PORT)
    return await self.wait_for_response()

  # ── Vehicle state ──

  async def wake(self):
    log.info("waking vehicle...")
    await self.send_rke(RKE_ACTION_WAKE_VEHICLE)
    return await self.wait_for_response()

  async def remote_drive(self):
    log.info("enabling remote drive...")
    await self.send_rke(RKE_ACTION_REMOTE_DRIVE)
    return await self.wait_for_response()

  async def auto_secure(self):
    log.info("auto-securing vehicle...")
    await self.send_rke(RKE_ACTION_AUTO_SECURE_VEHICLE)
    return await self.wait_for_response()

  # ── Closure control (individual doors/closures) ──

  async def open_front_driver_door(self):
    log.info("opening front driver door...")
    await self.send_closure_move(front_driver=CLOSURE_MOVE_OPEN)
    return await self.wait_for_response()

  async def close_front_driver_door(self):
    log.info("closing front driver door...")
    await self.send_closure_move(front_driver=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  async def open_front_passenger_door(self):
    log.info("opening front passenger door...")
    await self.send_closure_move(front_passenger=CLOSURE_MOVE_OPEN)
    return await self.wait_for_response()

  async def close_front_passenger_door(self):
    log.info("closing front passenger door...")
    await self.send_closure_move(front_passenger=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  async def open_rear_driver_door(self):
    log.info("opening rear driver door...")
    await self.send_closure_move(rear_driver=CLOSURE_MOVE_OPEN)
    return await self.wait_for_response()

  async def close_rear_driver_door(self):
    log.info("closing rear driver door...")
    await self.send_closure_move(rear_driver=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  async def open_rear_passenger_door(self):
    log.info("opening rear passenger door...")
    await self.send_closure_move(rear_passenger=CLOSURE_MOVE_OPEN)
    return await self.wait_for_response()

  async def close_rear_passenger_door(self):
    log.info("closing rear passenger door...")
    await self.send_closure_move(rear_passenger=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  async def open_tonneau(self):
    log.info("opening tonneau...")
    await self.send_closure_move(tonneau=CLOSURE_MOVE_OPEN)
    return await self.wait_for_response()

  async def close_tonneau(self):
    log.info("closing tonneau...")
    await self.send_closure_move(tonneau=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  # ── Key fob button simulation ──

  async def single_press_top(self):
    await self.send_rke(RKE_ACTION_SINGLE_PRESS_TOP)
    return await self.wait_for_response()

  async def double_press_top(self):
    await self.send_rke(RKE_ACTION_DOUBLE_PRESS_TOP)
    return await self.wait_for_response()

  async def triple_press_top(self):
    await self.send_rke(RKE_ACTION_TRIPLE_PRESS_TOP)
    return await self.wait_for_response()

  async def hold_top(self):
    await self.send_rke(RKE_ACTION_HOLD_TOP)
    return await self.wait_for_response()

  async def single_press_front(self):
    await self.send_rke(RKE_ACTION_SINGLE_PRESS_FRONT)
    return await self.wait_for_response()

  async def double_press_front(self):
    await self.send_rke(RKE_ACTION_DOUBLE_PRESS_FRONT)
    return await self.wait_for_response()

  async def single_press_back(self):
    await self.send_rke(RKE_ACTION_SINGLE_PRESS_BACK)
    return await self.wait_for_response()

  async def double_press_back(self):
    await self.send_rke(RKE_ACTION_DOUBLE_PRESS_BACK)
    return await self.wait_for_response()

  # ── Infotainment commands ──

  async def send_infotainment(self, action_bytes):
    if self.infotainment_key is None:
      log.error("infotainment session not established")
      return "no_infotainment"

    # extrapolate the vehicle's session clock forward from the anchor
    if self.infotainment_clock_anchor is not None:
      vehicle_clock = self.infotainment_clock_time + int(time.monotonic() - self.infotainment_clock_anchor)
    else:
      vehicle_clock = int(time.monotonic())
    expires_at = vehicle_clock + 10
    msg, req_uuid, req_tag = build_infotainment_command(
      self.infotainment_key, self.public_key_bytes, self.routing_address,
      self.vin, self.infotainment_epoch, self.infotainment_counter,
      expires_at, action_bytes,
    )
    self.infotainment_counter += 1
    await self.client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))

    # request_id for AES_GCM_PERSONALIZED requests = [SIGTYPE=5] ++ our encryption tag
    request_id = bytes([5]) + req_tag

    log.info(f"infotainment sent req_uuid={req_uuid.hex()} raw={ble_frame(msg).hex()}")
    # wait for routable response matching our request uuid
    deadline = asyncio.get_event_loop().time() + 5.0
    while asyncio.get_event_loop().time() < deadline:
      try:
        response = await asyncio.wait_for(self.rx_queue.get(), timeout=2.0)
        parsed = parse_routable_response(response)
        log.info(f"infotainment rx parsed={parsed}")
        # if the car returned a fresh session_info, re-anchor the clock
        si = parsed.get('session_info')
        if si and si.get('clock_time') is not None:
          self.infotainment_clock_time = si['clock_time']
          self.infotainment_clock_anchor = time.monotonic()
        if parsed.get('request_uuid') != req_uuid:
          continue
        ms = parsed.get('message_status') or {}
        status = ms.get('operation_status')
        fault = ms.get('fault') or 0

        # If the response carries an encrypted payload, decrypt it and stash on session.
        self.last_response_plaintext = None
        rsig = parsed.get('response_sig')
        ciphertext = parsed.get('payload')
        if rsig and ciphertext and rsig.get('nonce') and rsig.get('tag'):
          try:
            aad = build_response_aad(
              self.vin, DOMAIN_INFOTAINMENT,
              rsig.get('counter') or 0,
              parsed.get('flags') or 0,
              request_id, fault,
            )
            self.last_response_plaintext = decrypt_gcm(
              self.infotainment_key, rsig['nonce'], ciphertext, aad, rsig['tag'])
          except Exception as e:
            log.warning(f"response decrypt failed: {e}")

        if status in (None, 0) and fault == 0:
          return "ok"
        return f"status={status},fault={fault}"
      except asyncio.TimeoutError:
        break
    return "timeout"

  async def flash_lights(self):
    log.info("flashing lights...")
    return await self.send_infotainment(action_flash_lights())

  async def honk_horn(self):
    log.info("honking horn...")
    return await self.send_infotainment(action_honk_horn())

  async def set_sentry_mode(self, on=True):
    log.info(f"sentry mode {'on' if on else 'off'}...")
    return await self.send_infotainment(action_sentry_mode(on))

  async def trigger_homelink(self):
    log.info("triggering homelink...")
    return await self.send_infotainment(action_trigger_homelink())

  async def vent_windows(self):
    log.info("venting windows...")
    return await self.send_infotainment(action_window(vent=True))

  async def close_windows(self):
    log.info("closing windows...")
    return await self.send_infotainment(action_window(close=True))

  async def hvac_on(self):
    log.info("hvac on...")
    return await self.send_infotainment(action_hvac_auto(on=True))

  async def hvac_off(self):
    log.info("hvac off...")
    return await self.send_infotainment(action_hvac_auto(on=False))

  async def steering_wheel_heater(self, on=True):
    log.info(f"steering wheel heater {'on' if on else 'off'}...")
    return await self.send_infotainment(action_hvac_steering_wheel_heater(on))

  async def set_hvac_temp(self, driver_temp=None, passenger_temp=None):
    log.info(f"setting hvac temp driver={driver_temp} passenger={passenger_temp}...")
    return await self.send_infotainment(action_hvac_temp(driver_temp, passenger_temp))

  async def seat_heater(self, seat, level):
    log.info(f"seat heater seat={seat} level={level}...")
    return await self.send_infotainment(action_seat_heater(seat, level))

  async def media_toggle(self):
    log.info("toggling media playback...")
    return await self.send_infotainment(action_media_toggle_playback())

  async def media_next(self):
    log.info("next track...")
    return await self.send_infotainment(action_media_next_track())

  async def media_prev(self):
    log.info("previous track...")
    return await self.send_infotainment(action_media_previous_track())

  async def start_charging(self):
    log.info("starting charge...")
    return await self.send_infotainment(action_charging_start())

  async def stop_charging(self):
    log.info("stopping charge...")
    return await self.send_infotainment(action_charging_stop())

  async def set_charge_limit(self, percent):
    log.info(f"setting charge limit to {percent}%...")
    return await self.send_infotainment(action_set_charge_limit(percent))

  async def bioweapon_mode(self, on=True):
    log.info(f"bioweapon mode {'on' if on else 'off'}...")
    return await self.send_infotainment(action_bioweapon_mode(on))

  async def set_vehicle_name(self, name):
    log.info(f"setting vehicle name to '{name}'...")
    return await self.send_infotainment(action_set_vehicle_name(name))

  async def ping(self):
    return await self.send_infotainment(action_ping())

  async def get_vehicle_data(self, kinds):
    """Request each kind separately (BLE response MTU is small). Fold all successes into car_state."""
    errors = []
    any_ok = False
    for k in kinds:
      result = await self.send_infotainment(action_get_vehicle_data([k]))
      if result != "ok":
        errors.append(f"k{k}:{result}")
        continue
      if self.last_response_plaintext is not None:
        parse_vehicle_data(self.last_response_plaintext, self.car_state)
        any_ok = True
    if any_ok:
      self.car_state['infotainmentUpdatedAt'] = time.monotonic()
    if errors:
      return "ok_partial: " + ",".join(errors) if any_ok else errors[0]
    return "ok"


async def scan_for_teslas():
  log.info("scanning for Tesla BLE devices...")
  devices = await BleakScanner.discover(timeout=SCAN_DURATION)
  teslas = [d for d in devices if d.name and TESLA_BLE_NAME_RE.match(d.name)]
  for t in teslas:
    log.info(f"found Tesla: {t.name} ({t.address})")
  return teslas


async def connect_to_tesla(device, vin):
  """Open BLE connection and return a bare TeslaSession (no session negotiated yet)."""
  log.info(f"connecting to {device.name} ({device.address})...")
  private_key, public_key_bytes = load_or_create_key(TESLA_KEY_PATH)
  kid = key_id(public_key_bytes)
  rx_queue = asyncio.Queue()
  client = BleakClient(device.address)
  await client.connect(timeout=15.0)
  log.info(f"connected to {device.name}")
  await client.start_notify(TESLA_READ_UUID, make_reassembler(rx_queue))
  return TeslaSession(client, rx_queue, private_key, public_key_bytes, kid, vin=vin)


CLOSURE_FIELDS = (
  'frontDriverDoor', 'frontPassengerDoor', 'rearDriverDoor', 'rearPassengerDoor',
  'rearTrunk', 'frontTrunk', 'chargePort', 'tonneau',
)


def publish_state(pm, session, last_event=""):
  msg = messaging.new_message('teslaState')
  s = msg.teslaState
  s.connected = bool(session and session.client.is_connected)
  s.whitelisted = bool(session and session.whitelisted)
  s.infotainmentReady = bool(session and session.infotainment_ready)
  s.lastEvent = last_event

  if session is not None:
    car = s.car
    cs = session.car_state
    # VCSEC status
    car.lockState = int(cs.get('lockState') or 0)
    car.sleepStatus = int(cs.get('sleepStatus') or 0)
    car.userPresence = int(cs.get('userPresence') or 0)
    for f in CLOSURE_FIELDS:
      setattr(car, f, int(cs.get(f) or 0))
    # Infotainment data (populated by GetVehicleData)
    car.chargePercent = float(cs.get('chargePercent') or 0.0)
    car.batteryRangeMiles = float(cs.get('batteryRangeMiles') or 0.0)
    car.chargingState = str(cs.get('chargingState') or '')
    car.chargeLimitSoc = int(cs.get('chargeLimitSoc') or 0)
    car.chargerPower = float(cs.get('chargerPower') or 0.0)
    car.insideTempC = float(cs.get('insideTempC') or 0.0)
    car.outsideTempC = float(cs.get('outsideTempC') or 0.0)
    car.hvacOn = bool(cs.get('hvacOn') or False)
    car.driverTempSetpointC = float(cs.get('driverTempSetpointC') or 0.0)
    car.passengerTempSetpointC = float(cs.get('passengerTempSetpointC') or 0.0)
    car.speedMph = float(cs.get('speedMph') or 0.0)
    car.gear = str(cs.get('gear') or '')
    car.heading = float(cs.get('heading') or 0.0)
    car.latitude = float(cs.get('latitude') or 0.0)
    car.longitude = float(cs.get('longitude') or 0.0)
    car.odometerMiles = float(cs.get('odometerMiles') or 0.0)
    car.mediaPlaying = bool(cs.get('mediaPlaying') or False)
    car.mediaTrack = str(cs.get('mediaTrack') or '')
    car.mediaArtist = str(cs.get('mediaArtist') or '')
    car.vcsecUpdatedAt = float(cs.get('vcsecUpdatedAt') or 0.0)
    car.infotainmentUpdatedAt = float(cs.get('infotainmentUpdatedAt') or 0.0)

  pm.send('teslaState', msg)


async def dispatch_command(session, command, arg, pm):
  log.info(f"dispatch: command={command!r} arg={arg!r}")

  # Session setup commands
  if command == "whitelist":
    publish_state(pm, session, "whitelist=awaiting_tap")
    ok = await session.whitelist()
    if ok:
      await session.negotiate_vcsec()
      if session.whitelisted and session.vin:
        await session.negotiate_infotainment()
    return "ok" if ok else "timeout"

  if command == "reconnect":
    await session.negotiate_vcsec()
    if session.whitelisted and session.vin:
      await session.negotiate_infotainment()
    return "ok" if session.whitelisted else "not_whitelisted"

  if command == "get_status":
    return await session.request_status()

  if command == "data":
    # arg is a comma-separated list of kinds, or "all" for everything
    if not session.infotainment_ready:
      return "no_infotainment"
    tokens = [t.strip() for t in arg.split(",")] if arg else ["charge", "climate", "drive", "location", "media"]
    if tokens == ["all"]:
      tokens = list(GET_VEHICLE_DATA_KINDS.keys())
    kinds = [GET_VEHICLE_DATA_KINDS[t] for t in tokens if t in GET_VEHICLE_DATA_KINDS]
    if not kinds:
      return f"bad_arg: {arg!r}"
    return await session.get_vehicle_data(kinds)

  # Gate VCSEC-requiring commands
  if not session.whitelisted:
    return "not_whitelisted"

  try:
    # VCSEC (RKE)
    if command == "unlock":              return await session.unlock()
    if command == "lock":                return await session.lock()
    if command == "trunk":               return await session.open_trunk()
    if command == "close_trunk":         return await session.close_trunk()
    if command == "frunk":               return await session.open_frunk()
    if command == "charge_port":         return await session.open_charge_port()
    if command == "close_charge_port":   return await session.close_charge_port()
    if command == "wake":                return await session.wake()
    if command == "auto_secure":         return await session.auto_secure()
    if command == "remote_drive":        return await session.remote_drive()
    # Doors
    if command == "door_fd_open":        return await session.open_front_driver_door()
    if command == "door_fd_close":       return await session.close_front_driver_door()
    if command == "door_fp_open":        return await session.open_front_passenger_door()
    if command == "door_fp_close":       return await session.close_front_passenger_door()
    if command == "door_rd_open":        return await session.open_rear_driver_door()
    if command == "door_rd_close":       return await session.close_rear_driver_door()
    if command == "door_rp_open":        return await session.open_rear_passenger_door()
    if command == "door_rp_close":       return await session.close_rear_passenger_door()
    if command == "tonneau_open":        return await session.open_tonneau()
    if command == "tonneau_close":       return await session.close_tonneau()

    # Infotainment (requires infotainment session)
    if not session.infotainment_ready:
      return "no_infotainment"
    if command == "honk":                return await session.honk_horn()
    if command == "flash":               return await session.flash_lights()
    if command == "homelink":            return await session.trigger_homelink()
    if command == "vent":                return await session.vent_windows()
    if command == "close_windows":       return await session.close_windows()
    if command == "ping":                return await session.ping()
    if command == "sentry":              return await session.set_sentry_mode(arg == "on")
    if command == "bioweapon":           return await session.bioweapon_mode(arg == "on")
    if command == "steering_heat":       return await session.steering_wheel_heater(arg == "on")
    if command == "hvac":
      return await (session.hvac_on() if arg == "on" else session.hvac_off())
    if command == "temp":
      parts = [float(x) for x in arg.split(",")] if arg else []
      d = parts[0] if len(parts) > 0 else None
      p = parts[1] if len(parts) > 1 else None
      return await session.set_hvac_temp(d, p)
    if command == "seat_heat":
      # arg format: "<seat>,<level>" where seat is fl/fr/rl/rc/rr or driver/passenger,
      # and level is off/low/med/high
      seat_str, level_str = arg.split(",")
      seat = SEAT_POSITIONS.get(seat_str.strip().lower())
      level = SEAT_HEATER_LEVELS.get(level_str.strip().lower())
      if seat is None or level is None:
        return f"bad_arg: seat={seat_str} level={level_str}"
      return await session.seat_heater(seat, level)
    if command == "media":
      if arg == "play": return await session.media_toggle()
      if arg == "next": return await session.media_next()
      if arg == "prev": return await session.media_prev()
    if command == "charge":
      if arg == "start": return await session.start_charging()
      if arg == "stop":  return await session.stop_charging()
    if command == "charge_limit":        return await session.set_charge_limit(int(arg))
    if command == "name":                return await session.set_vehicle_name(arg)
    return "unknown_command"
  except Exception as e:
    log.error(f"dispatch error for {command}: {e}")
    return f"error: {e}"


AUTO_REFRESH_INTERVAL = 60.0  # seconds
AUTO_REFRESH_KINDS = [2, 3, 4, 7, 15]  # charge, climate, drive, location, media


async def command_loop(session, sm, pm):
  last_auto_refresh = 0.0
  while session.client.is_connected:
    # drain unsolicited rx (e.g. VCSEC VehicleStatus broadcasts)
    updated = False
    while not session.rx_queue.empty():
      msg = session.rx_queue.get_nowait()
      parsed = parse_from_vcsec(msg)
      if session._update_from_vcsec(parsed):
        updated = True
    if updated:
      publish_state(pm, session, "vcsec_update")

    # periodic infotainment data refresh — keeps home screen fresh
    now = time.monotonic()
    if session.infotainment_ready and now - last_auto_refresh > AUTO_REFRESH_INTERVAL:
      last_auto_refresh = now
      try:
        result = await session.get_vehicle_data(AUTO_REFRESH_KINDS)
        publish_state(pm, session, f"auto_refresh={result}")
      except Exception as e:
        log.warning(f"auto refresh failed: {e}")

    sm.update(0)
    if sm.updated.get('teslaCommand'):
      cmd = sm['teslaCommand']
      result = await dispatch_command(session, cmd.command, cmd.arg, pm)
      publish_state(pm, session, f"{cmd.command}={result}")
    await asyncio.sleep(0.05)


async def run():
  sm = messaging.SubMaster(['teslaCommand'])
  pm = messaging.PubMaster(['teslaState'])
  publish_state(pm, None, "idle")

  while True:
    try:
      with open(TESLA_VIN_PATH) as f:
        vin = f.read().strip()
    except FileNotFoundError:
      log.info(f"{TESLA_VIN_PATH} not found, retrying...")
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    teslas = await scan_for_teslas()
    if not teslas:
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    expected_name = "S" + hashlib.sha1(vin.encode()).hexdigest()[:16] + "C"
    target = next((t for t in teslas if t.name == expected_name), None)
    if target is None:
      log.info(f"target {expected_name} not found")
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    session = None
    try:
      session = await connect_to_tesla(target, vin)
      await session.negotiate_vcsec()
      if session.whitelisted:
        await session.negotiate_infotainment()
      publish_state(pm, session, "connected" if session.whitelisted else "needs_whitelist")
      await command_loop(session, sm, pm)
      log.info(f"disconnected from {target.name}")
    except Exception as e:
      log.error(f"connection failed: {e}")
    finally:
      publish_state(pm, None, "disconnected")

    await asyncio.sleep(SCAN_INTERVAL)


def main():
  log.info("teslad started")
  asyncio.run(run())


if __name__ == "__main__":
  main()
