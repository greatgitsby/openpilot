"""Tesla BLE protocol message builders and parsers.

Defines all enums, field numbers, and message construction/parsing for the
Tesla vehicle-command protobuf protocol (VCSEC, CarServer, Signatures,
UniversalMessage) without requiring compiled .proto files.
"""

from __future__ import annotations

from enum import IntEnum

from openpilot.tools.tesla_ble.protobuf import (
  WIRE_BYTES,
  WIRE_VARINT,
  WIRE_32BIT,
  decode_fields,
  encode_message,
  encode_nested,
  get_bytes,
  get_field,
  get_int,
)


# ---------------------------------------------------------------------------
# Enums — UniversalMessage
# ---------------------------------------------------------------------------

class Domain(IntEnum):
  BROADCAST = 0
  VEHICLE_SECURITY = 2
  INFOTAINMENT = 3


class OperationStatus(IntEnum):
  OK = 0
  WAIT = 1
  ERROR = 2


class MessageFault(IntEnum):
  NONE = 0
  BUSY = 1
  TIMEOUT = 2
  UNKNOWN_KEY_ID = 3
  INACTIVE_KEY = 4
  INVALID_SIGNATURE = 5
  INVALID_TOKEN_OR_COUNTER = 6
  INSUFFICIENT_PRIVILEGES = 7
  INVALID_DOMAINS = 8
  INVALID_COMMAND = 9
  DECODING = 10
  INTERNAL = 11
  WRONG_PERSONALIZATION = 12
  BAD_PARAMETER = 13
  KEYCHAIN_IS_FULL = 14
  INCORRECT_EPOCH = 15
  IV_INCORRECT_LENGTH = 16
  TIME_EXPIRED = 17
  NOT_PROVISIONED_WITH_IDENTITY = 18
  COULD_NOT_HASH_METADATA = 19
  TIME_TO_LIVE_TOO_LONG = 20
  REMOTE_ACCESS_DISABLED = 21
  REMOTE_SERVICE_ACCESS_DISABLED = 22
  COMMAND_REQUIRES_ACCOUNT_CREDENTIALS = 23
  REQUEST_MTU_EXCEEDED = 24
  RESPONSE_MTU_EXCEEDED = 25
  REPEATED_COUNTER = 26
  INVALID_KEY_HANDLE = 27
  REQUIRES_RESPONSE_ENCRYPTION = 28


class Flags(IntEnum):
  USER_COMMAND = 0
  ENCRYPT_RESPONSE = 1


# ---------------------------------------------------------------------------
# Enums — Signatures
# ---------------------------------------------------------------------------

class SignatureType(IntEnum):
  AES_GCM = 0
  AES_GCM_PERSONALIZED = 5
  HMAC = 6
  HMAC_PERSONALIZED = 8
  AES_GCM_RESPONSE = 9


class Tag(IntEnum):
  SIGNATURE_TYPE = 0
  DOMAIN = 1
  PERSONALIZATION = 2
  EPOCH = 3
  EXPIRES_AT = 4
  COUNTER = 5
  CHALLENGE = 6
  FLAGS = 7
  REQUEST_HASH = 8
  FAULT = 9
  END = 255


class SessionInfoStatus(IntEnum):
  OK = 0
  KEY_NOT_ON_WHITELIST = 1


# ---------------------------------------------------------------------------
# Enums — VCSEC
# ---------------------------------------------------------------------------

class VCSECSignatureType(IntEnum):
  NONE = 0
  PRESENT_KEY = 2


class KeyFormFactor(IntEnum):
  UNKNOWN = 0
  NFC_CARD = 1
  IOS_DEVICE = 6
  ANDROID_DEVICE = 7
  CLOUD_KEY = 9


class InformationRequestType(IntEnum):
  GET_STATUS = 0
  GET_WHITELIST_INFO = 5
  GET_WHITELIST_ENTRY_INFO = 6


class RKEAction(IntEnum):
  UNLOCK = 0
  LOCK = 1
  REMOTE_DRIVE = 20
  AUTO_SECURE_VEHICLE = 29
  WAKE_VEHICLE = 30


class ClosureMoveType(IntEnum):
  NONE = 0
  MOVE = 1
  STOP = 2
  OPEN = 3
  CLOSE = 4


class ClosureState(IntEnum):
  CLOSED = 0
  OPEN = 1
  AJAR = 2
  UNKNOWN = 3
  FAILED_UNLATCH = 4
  OPENING = 5
  CLOSING = 6


class VehicleLockState(IntEnum):
  UNLOCKED = 0
  LOCKED = 1
  INTERNAL_LOCKED = 2
  SELECTIVE_UNLOCKED = 3


class VehicleSleepStatus(IntEnum):
  UNKNOWN = 0
  AWAKE = 1
  ASLEEP = 2


class UserPresence(IntEnum):
  UNKNOWN = 0
  NOT_PRESENT = 1
  PRESENT = 2


# ---------------------------------------------------------------------------
# Enums — Keys
# ---------------------------------------------------------------------------

class KeyRole(IntEnum):
  NONE = 0
  SERVICE = 1
  OWNER = 2
  DRIVER = 3
  FM = 4
  VEHICLE_MONITOR = 5
  CHARGING_MANAGER = 6
  GUEST = 8


# ---------------------------------------------------------------------------
# Enums — CarServer
# ---------------------------------------------------------------------------

class ClimateKeeperAction(IntEnum):
  OFF = 0
  ON = 1
  DOG = 2
  CAMP = 3


class SeatPosition(IntEnum):
  FRONT_LEFT = 0
  FRONT_RIGHT = 1
  REAR_LEFT = 2
  REAR_CENTER = 4
  REAR_RIGHT = 5
  THIRD_ROW_LEFT = 6
  THIRD_ROW_RIGHT = 7


class SeatHeaterLevel(IntEnum):
  OFF = 0
  LOW = 1
  MED = 2
  HIGH = 3


class AutoGlassPosition(IntEnum):
  UNKNOWN = 0
  VENT = 1
  CLOSE = 2


# ===================================================================
# Message builders — UniversalMessage / RoutableMessage
# ===================================================================

def build_destination(domain: Domain | None = None, routing_address: bytes | None = None) -> bytes:
  """Build a Destination sub-message."""
  fields = []
  if domain is not None:
    fields.append((1, WIRE_VARINT, int(domain)))  # field 1: domain
  if routing_address is not None:
    fields.append((2, WIRE_BYTES, routing_address))  # field 2: routing_address
  return encode_message(fields)


def build_routable_message(
  to_domain: Domain,
  from_address: bytes | None = None,
  payload: bytes | None = None,
  session_info_request: bytes | None = None,
  session_info: bytes | None = None,
  signature_data: bytes | None = None,
  request_uuid: bytes | None = None,
  flags: int = 0,
) -> bytes:
  """Build a RoutableMessage (the top-level BLE envelope).

  Exactly one of payload, session_info_request, or session_info should be set.
  """
  fields = []
  # field 6: to_destination
  fields.append(encode_nested(6, [(1, WIRE_VARINT, int(to_domain))]))
  # field 7: from_destination
  if from_address is not None:
    fields.append(encode_nested(7, [(2, WIRE_BYTES, from_address)]))
  # payload (oneof): field 10 = protobuf_message_as_bytes, 14 = session_info_request, 15 = session_info
  if payload is not None:
    fields.append((10, WIRE_BYTES, payload))
  if session_info_request is not None:
    fields.append((14, WIRE_BYTES, session_info_request))
  if session_info is not None:
    fields.append((15, WIRE_BYTES, session_info))
  # field 13: signature_data
  if signature_data is not None:
    fields.append((13, WIRE_BYTES, signature_data))
  # field 50: request_uuid
  if request_uuid is not None:
    fields.append((50, WIRE_BYTES, request_uuid))
  # field 52: flags
  if flags:
    fields.append((52, WIRE_VARINT, flags))
  return encode_message(fields)


def build_session_info_request(public_key: bytes) -> bytes:
  """Build a SessionInfoRequest message (field 1 = public_key)."""
  return encode_message([(1, WIRE_BYTES, public_key)])


# ===================================================================
# Message builders — Signatures
# ===================================================================

def build_key_identity(public_key: bytes | None = None, handle: int | None = None) -> bytes:
  """Build a KeyIdentity message."""
  fields = []
  if public_key is not None:
    fields.append((1, WIRE_BYTES, public_key))
  if handle is not None:
    fields.append((3, WIRE_VARINT, handle))
  return encode_message(fields)


def build_aes_gcm_sig_data(epoch: bytes, nonce: bytes, counter: int, expires_at: int, tag: bytes) -> bytes:
  """Build AES_GCM_Personalized_Signature_Data."""
  return encode_message([
    (1, WIRE_BYTES, epoch),
    (2, WIRE_BYTES, nonce),
    (3, WIRE_VARINT, counter),
    (4, WIRE_32BIT, expires_at),
    (5, WIRE_BYTES, tag),
  ])


def build_hmac_sig_data(epoch: bytes, counter: int, expires_at: int, tag: bytes) -> bytes:
  """Build HMAC_Personalized_Signature_Data."""
  return encode_message([
    (1, WIRE_BYTES, epoch),
    (2, WIRE_VARINT, counter),
    (3, WIRE_32BIT, expires_at),
    (4, WIRE_BYTES, tag),
  ])


def build_signature_data(
  signer_identity: bytes,
  aes_gcm_data: bytes | None = None,
  session_info_tag: bytes | None = None,
  hmac_data: bytes | None = None,
) -> bytes:
  """Build a SignatureData message."""
  fields = [(1, WIRE_BYTES, signer_identity)]
  if aes_gcm_data is not None:
    fields.append((5, WIRE_BYTES, aes_gcm_data))
  if session_info_tag is not None:
    fields.append((6, WIRE_BYTES, session_info_tag))
  if hmac_data is not None:
    fields.append((8, WIRE_BYTES, hmac_data))
  return encode_message(fields)


# ===================================================================
# Message builders — VCSEC
# ===================================================================

def build_unsigned_message(
  information_request: bytes | None = None,
  rke_action: RKEAction | None = None,
  closure_move_request: bytes | None = None,
  whitelist_operation: bytes | None = None,
) -> bytes:
  """Build an UnsignedMessage for VCSEC domain."""
  fields = []
  if information_request is not None:
    fields.append((1, WIRE_BYTES, information_request))
  if rke_action is not None:
    fields.append((2, WIRE_VARINT, int(rke_action)))
  if closure_move_request is not None:
    fields.append((4, WIRE_BYTES, closure_move_request))
  if whitelist_operation is not None:
    fields.append((16, WIRE_BYTES, whitelist_operation))
  return encode_message(fields)


def build_information_request(
  request_type: InformationRequestType,
  key_id: bytes | None = None,
  public_key: bytes | None = None,
  slot: int | None = None,
) -> bytes:
  """Build an InformationRequest message."""
  fields = [(1, WIRE_VARINT, int(request_type))]
  if key_id is not None:
    fields.append(encode_nested(2, [(1, WIRE_BYTES, key_id)]))
  if public_key is not None:
    fields.append((3, WIRE_BYTES, public_key))
  if slot is not None:
    fields.append((4, WIRE_VARINT, slot))
  return encode_message(fields)


def build_closure_move_request(
  front_driver_door: ClosureMoveType = ClosureMoveType.NONE,
  front_passenger_door: ClosureMoveType = ClosureMoveType.NONE,
  rear_driver_door: ClosureMoveType = ClosureMoveType.NONE,
  rear_passenger_door: ClosureMoveType = ClosureMoveType.NONE,
  rear_trunk: ClosureMoveType = ClosureMoveType.NONE,
  front_trunk: ClosureMoveType = ClosureMoveType.NONE,
  charge_port: ClosureMoveType = ClosureMoveType.NONE,
  tonneau: ClosureMoveType = ClosureMoveType.NONE,
) -> bytes:
  """Build a ClosureMoveRequest message."""
  fields = []
  for i, val in enumerate([
    front_driver_door, front_passenger_door, rear_driver_door, rear_passenger_door,
    rear_trunk, front_trunk, charge_port, tonneau,
  ], start=1):
    if val != ClosureMoveType.NONE:
      fields.append((i, WIRE_VARINT, int(val)))
  return encode_message(fields)


def build_whitelist_operation(
  add_public_key: bytes | None = None,
  remove_public_key: bytes | None = None,
  key_role: KeyRole | None = None,
  metadata_key_form_factor: KeyFormFactor | None = None,
) -> bytes:
  """Build a WhitelistOperation message (simplified for add/remove)."""
  fields = []
  if add_public_key is not None:
    # field 1: addPublicKeyToWhitelist (PublicKey message, field 1 = raw bytes)
    fields.append(encode_nested(1, [(1, WIRE_BYTES, add_public_key)]))
  if remove_public_key is not None:
    # field 2: removePublicKeyFromWhitelist
    fields.append(encode_nested(2, [(1, WIRE_BYTES, remove_public_key)]))
  if key_role is not None:
    # field 4 in addKeyToWhitelistAndAddPermissions -> keyRole
    # We use PermissionChange (field 3) for simplicity:
    # PermissionChange: key (field 1), secondsToBeActive (field 3), keyRole (field 4)
    # But for simple add, we put keyRole directly into the permission change
    pass
  if metadata_key_form_factor is not None:
    # field 6: metadataForKey (KeyMetadata: field 1 = keyFormFactor)
    fields.append(encode_nested(6, [(1, WIRE_VARINT, int(metadata_key_form_factor))]))
  return encode_message(fields)


def build_whitelist_operation_add(
  public_key: bytes,
  key_role: KeyRole,
  form_factor: KeyFormFactor,
) -> bytes:
  """Build a WhitelistOperation to add a key with role and form factor."""
  # addPublicKeyToWhitelist: PublicKey (field 1, raw bytes in field 1)
  pub_key_msg = encode_message([(1, WIRE_BYTES, public_key)])
  # addAndEnableKeyToWhitelistAndAddPermissions (field 9):
  #   PermissionChange: key (1), secondsToBeActive (3), keyRole (4)
  perm_change = encode_message([
    encode_nested(1, [(1, WIRE_BYTES, public_key)]),  # key
    (4, WIRE_VARINT, int(key_role)),  # keyRole
  ])
  # metadataForKey (field 6): KeyMetadata.keyFormFactor (field 1)
  metadata = encode_message([(1, WIRE_VARINT, int(form_factor))])
  return encode_message([
    (1, WIRE_BYTES, pub_key_msg),  # addPublicKeyToWhitelist
    (6, WIRE_BYTES, metadata),  # metadataForKey
    (9, WIRE_BYTES, perm_change),  # addAndEnableKeyToWhitelistAndAddPermissions
  ])


# ===================================================================
# Message builders — CarServer (Infotainment domain)
# ===================================================================

def _build_action(vehicle_action_field: int, action_msg: bytes = b'') -> bytes:
  """Wrap an action message into Action -> VehicleAction -> specific action."""
  vehicle_action = encode_message([(vehicle_action_field, WIRE_BYTES, action_msg)])
  return encode_message([(2, WIRE_BYTES, vehicle_action)])  # Action.vehicleAction = field 2


def build_hvac_auto_action(power_on: bool) -> bytes:
  """HvacAutoAction — field 10 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(power_on))])
  return _build_action(10, msg)


def build_hvac_temperature_action(driver_temp: float, passenger_temp: float | None = None) -> bytes:
  """HvacTemperatureAdjustmentAction — field 14 in VehicleAction."""
  import struct as _struct
  fields = [(6, WIRE_32BIT, _struct.unpack('<I', _struct.pack('<f', driver_temp))[0])]
  if passenger_temp is not None:
    fields.append((7, WIRE_32BIT, _struct.unpack('<I', _struct.pack('<f', passenger_temp))[0]))
  msg = encode_message(fields)
  return _build_action(14, msg)


def build_hvac_steering_wheel_heater_action(power_on: bool) -> bytes:
  """HvacSteeringWheelHeaterAction — field 13 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(power_on))])
  return _build_action(13, msg)


def build_hvac_seat_heater_actions(seat_heaters: list[tuple[SeatPosition, SeatHeaterLevel]]) -> bytes:
  """HvacSeatHeaterActions — field 36 in VehicleAction.

  Each element is (SeatPosition, SeatHeaterLevel).
  HvacSeatHeaterAction: seat_position (field 1), seat_heater_level (field 2)
  HvacSeatHeaterActions: repeated hvacSeatHeaterAction (field 1)
  """
  action_msgs = []
  for seat, level in seat_heaters:
    single = encode_message([
      (1, WIRE_VARINT, int(seat)),
      (2, WIRE_VARINT, int(level)),
    ])
    action_msgs.append((1, WIRE_BYTES, single))
  msg = encode_message(action_msgs)
  return _build_action(36, msg)


def build_hvac_bioweapon_mode_action(on: bool) -> bytes:
  """HvacBioweaponModeAction — field 35 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(on))])
  return _build_action(35, msg)


def build_hvac_climate_keeper_action(action: ClimateKeeperAction) -> bytes:
  """HvacClimateKeeperAction — field 44 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(action))])
  return _build_action(44, msg)


def build_hvac_preconditioning_max_action(on: bool) -> bytes:
  """HvacSetPreconditioningMaxAction — field 12 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(on))])
  return _build_action(12, msg)


def build_cabin_overheat_protection_action(on: bool, fan_only: bool = False) -> bytes:
  """SetCabinOverheatProtectionAction — field 50 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(on)), (2, WIRE_VARINT, int(fan_only))])
  return _build_action(50, msg)


def build_charging_set_limit_action(percent: int) -> bytes:
  """ChargingSetLimitAction — field 5 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, percent)])
  return _build_action(5, msg)


def build_charging_start_stop_action(start: bool) -> bytes:
  """ChargingStartStopAction — field 6 in VehicleAction.

  oneof: field 2 = start (Void), field 5 = stop (Void)
  """
  if start:
    msg = encode_message([(2, WIRE_BYTES, b'')])  # start
  else:
    msg = encode_message([(5, WIRE_BYTES, b'')])  # stop
  return _build_action(6, msg)


def build_set_charging_amps_action(amps: int) -> bytes:
  """SetChargingAmpsAction — field 43 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, amps)])
  return _build_action(43, msg)


def build_scheduled_charging_action(enabled: bool, charging_time: int = 0) -> bytes:
  """ScheduledChargingAction — field 41 in VehicleAction."""
  fields = [(1, WIRE_VARINT, int(enabled))]
  if charging_time:
    fields.append((2, WIRE_VARINT, charging_time))
  msg = encode_message(fields)
  return _build_action(41, msg)


def build_charge_port_door_open() -> bytes:
  """ChargePortDoorOpen — field 62 in VehicleAction."""
  return _build_action(62)


def build_charge_port_door_close() -> bytes:
  """ChargePortDoorClose — field 61 in VehicleAction."""
  return _build_action(61)


def build_flash_lights_action() -> bytes:
  """VehicleControlFlashLightsAction — field 26 in VehicleAction."""
  return _build_action(26)


def build_honk_horn_action() -> bytes:
  """VehicleControlHonkHornAction — field 27 in VehicleAction."""
  return _build_action(27)


def build_set_sentry_mode_action(on: bool) -> bytes:
  """VehicleControlSetSentryModeAction — field 30 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(on))])
  return _build_action(30, msg)


def build_set_valet_mode_action(on: bool, password: str = '') -> bytes:
  """VehicleControlSetValetModeAction — field 31 in VehicleAction."""
  fields = [(1, WIRE_VARINT, int(on))]
  if password:
    fields.append((2, WIRE_BYTES, password.encode()))
  msg = encode_message(fields)
  return _build_action(31, msg)


def build_pin_to_drive_action(on: bool, password: str = '') -> bytes:
  """VehicleControlSetPinToDriveAction — field 77 in VehicleAction."""
  fields = [(1, WIRE_VARINT, int(on))]
  if password:
    fields.append((2, WIRE_BYTES, password.encode()))
  msg = encode_message(fields)
  return _build_action(77, msg)


def build_window_action(vent: bool = False, close: bool = False) -> bytes:
  """VehicleControlWindowAction — field 34 in VehicleAction.

  oneof action: field 3 = vent (Void), field 4 = close (Void)
  """
  if vent:
    msg = encode_message([(3, WIRE_BYTES, b'')])
  elif close:
    msg = encode_message([(4, WIRE_BYTES, b'')])
  else:
    msg = b''
  return _build_action(34, msg)


def build_sunroof_action(vent: bool = False, close: bool = False) -> bytes:
  """VehicleControlSunroofOpenCloseAction — field 32 in VehicleAction.

  oneof action: field 3 = vent (Void), field 4 = close (Void), field 5 = open (Void)
  """
  if vent:
    msg = encode_message([(3, WIRE_BYTES, b'')])
  elif close:
    msg = encode_message([(4, WIRE_BYTES, b'')])
  else:
    msg = b''
  return _build_action(32, msg)


def build_trigger_homelink_action() -> bytes:
  """VehicleControlTriggerHomelinkAction — field 33 in VehicleAction."""
  return _build_action(33)


def build_set_speed_limit_action(limit_mph: float) -> bytes:
  """DrivingSetSpeedLimitAction — field 8 in VehicleAction.

  field 1: double limit_mph (wire type 1 = 64-bit)
  """
  import struct as _struct
  msg = encode_message([(1, WIRE_BYTES, _struct.pack('<d', limit_mph))])
  # Actually, double is wire type 1 (fixed 64-bit)
  msg = b''
  # Re-encode properly: field 1 as 64-bit fixed
  from openpilot.tools.tesla_ble.protobuf import WIRE_64BIT, encode_field
  msg = encode_field(1, WIRE_64BIT, _struct.unpack('<Q', _struct.pack('<d', limit_mph))[0])
  return _build_action(8, msg)


def build_speed_limit_activate_action(activate: bool, pin: str = '') -> bytes:
  """DrivingSpeedLimitAction — field 9 in VehicleAction."""
  fields = [(1, WIRE_VARINT, int(activate))]
  if pin:
    fields.append((2, WIRE_BYTES, pin.encode()))
  msg = encode_message(fields)
  return _build_action(9, msg)


def build_media_play_action() -> bytes:
  """MediaPlayAction — field 15 in VehicleAction."""
  return _build_action(15)


def build_media_next_track() -> bytes:
  """MediaNextTrack — field 19 in VehicleAction."""
  return _build_action(19)


def build_media_previous_track() -> bytes:
  """MediaPreviousTrack — field 20 in VehicleAction."""
  return _build_action(20)


def build_media_update_volume(volume_delta: int) -> bytes:
  """MediaUpdateVolume — field 16 in VehicleAction.

  MediaUpdateVolume: field 1 = media_volume (sint32)
  We use sint32 encoding (zigzag) for the delta.
  """
  # zigzag encode: (n << 1) ^ (n >> 31)
  zigzag = (volume_delta << 1) ^ (volume_delta >> 31)
  msg = encode_message([(1, WIRE_VARINT, zigzag)])
  return _build_action(16, msg)


def build_media_next_favorite() -> bytes:
  """MediaNextFavorite — field 17 in VehicleAction."""
  return _build_action(17)


def build_media_previous_favorite() -> bytes:
  """MediaPreviousFavorite — field 18 in VehicleAction."""
  return _build_action(18)


def build_set_vehicle_name_action(name: str) -> bytes:
  """SetVehicleNameAction — field 54 in VehicleAction."""
  msg = encode_message([(1, WIRE_BYTES, name.encode())])
  return _build_action(54, msg)


def build_schedule_software_update_action(offset_sec: int) -> bytes:
  """VehicleControlScheduleSoftwareUpdateAction — field 29 in VehicleAction.

  field 1: offset_sec (int32)
  """
  msg = encode_message([(1, WIRE_VARINT, offset_sec)])
  return _build_action(29, msg)


def build_cancel_software_update_action() -> bytes:
  """VehicleControlCancelSoftwareUpdateAction — field 25 in VehicleAction."""
  return _build_action(25)


def build_set_low_power_mode_action(on: bool) -> bytes:
  """SetLowPowerModeAction — field 130 in VehicleAction."""
  msg = encode_message([(1, WIRE_VARINT, int(on))])
  return _build_action(130, msg)


# ===================================================================
# Message parsers
# ===================================================================

def parse_routable_message(data: bytes) -> dict:
  """Parse a RoutableMessage into its components."""
  fields = decode_fields(data)
  result = {}

  # to_destination (field 6)
  to_dest = get_bytes(fields, 6)
  if to_dest:
    dest_fields = decode_fields(to_dest)
    result['to_domain'] = get_int(dest_fields, 1)
    to_addr = get_bytes(dest_fields, 2)
    if to_addr:
      result['to_address'] = to_addr

  # from_destination (field 7)
  from_dest = get_bytes(fields, 7)
  if from_dest:
    dest_fields = decode_fields(from_dest)
    result['from_domain'] = get_int(dest_fields, 1)
    from_addr = get_bytes(dest_fields, 2)
    if from_addr:
      result['from_address'] = from_addr

  # payload (field 10)
  result['payload'] = get_bytes(fields, 10)

  # signedMessageStatus (field 12)
  status_bytes = get_bytes(fields, 12)
  if status_bytes:
    sf = decode_fields(status_bytes)
    result['operation_status'] = get_int(sf, 1)
    result['message_fault'] = get_int(sf, 2)

  # signature_data (field 13)
  result['signature_data'] = get_bytes(fields, 13)

  # session_info_request (field 14)
  result['session_info_request'] = get_bytes(fields, 14)

  # session_info (field 15)
  result['session_info'] = get_bytes(fields, 15)

  # request_uuid (field 50)
  result['request_uuid'] = get_bytes(fields, 50)

  # uuid (field 51)
  result['uuid'] = get_bytes(fields, 51)

  # flags (field 52)
  result['flags'] = get_int(fields, 52)

  return result


def parse_session_info(data: bytes) -> dict:
  """Parse a SessionInfo message."""
  fields = decode_fields(data)
  return {
    'counter': get_int(fields, 1),
    'public_key': get_bytes(fields, 2),
    'epoch': get_bytes(fields, 3),
    'clock_time': get_field(fields, 4, 0),  # fixed32
    'status': get_int(fields, 5),
    'handle': get_int(fields, 6),
  }


def parse_from_vcsec_message(data: bytes) -> dict:
  """Parse a FromVCSECMessage."""
  fields = decode_fields(data)
  result = {}

  # vehicleStatus (field 1)
  vs_bytes = get_bytes(fields, 1)
  if vs_bytes:
    result['vehicle_status'] = parse_vehicle_status(vs_bytes)

  # commandStatus (field 4)
  cs_bytes = get_bytes(fields, 4)
  if cs_bytes:
    result['command_status'] = parse_command_status(cs_bytes)

  # whitelistInfo (field 16)
  wi_bytes = get_bytes(fields, 16)
  if wi_bytes:
    result['whitelist_info'] = parse_whitelist_info(wi_bytes)

  # whitelistEntryInfo (field 17)
  wei_bytes = get_bytes(fields, 17)
  if wei_bytes:
    result['whitelist_entry_info'] = parse_whitelist_entry_info(wei_bytes)

  # nominalError (field 46)
  ne_bytes = get_bytes(fields, 46)
  if ne_bytes:
    result['nominal_error'] = ne_bytes

  return result


def parse_vehicle_status(data: bytes) -> dict:
  """Parse a VehicleStatus message."""
  fields = decode_fields(data)
  result = {}

  # closureStatuses (field 1)
  cs_bytes = get_bytes(fields, 1)
  if cs_bytes:
    cs_fields = decode_fields(cs_bytes)
    result['closure_statuses'] = {
      'front_driver_door': get_int(cs_fields, 1),
      'front_passenger_door': get_int(cs_fields, 2),
      'rear_driver_door': get_int(cs_fields, 3),
      'rear_passenger_door': get_int(cs_fields, 4),
      'rear_trunk': get_int(cs_fields, 5),
      'front_trunk': get_int(cs_fields, 6),
      'charge_port': get_int(cs_fields, 7),
      'tonneau': get_int(cs_fields, 8),
    }

  result['vehicle_lock_state'] = get_int(fields, 2)
  result['vehicle_sleep_status'] = get_int(fields, 3)
  result['user_presence'] = get_int(fields, 4)

  return result


def parse_command_status(data: bytes) -> dict:
  """Parse a CommandStatus message."""
  fields = decode_fields(data)
  result = {'operation_status': get_int(fields, 1)}

  sms_bytes = get_bytes(fields, 2)
  if sms_bytes:
    sms_fields = decode_fields(sms_bytes)
    result['signed_message_status'] = {
      'counter': get_int(sms_fields, 1),
      'info': get_int(sms_fields, 2),
    }

  wos_bytes = get_bytes(fields, 3)
  if wos_bytes:
    wos_fields = decode_fields(wos_bytes)
    result['whitelist_operation_status'] = {
      'info': get_int(wos_fields, 1),
      'operation_status': get_int(wos_fields, 3),
    }

  return result


def parse_whitelist_info(data: bytes) -> dict:
  """Parse a WhitelistInfo message."""
  fields = decode_fields(data)
  entries = []
  for _, val in fields.get(2, []):
    if isinstance(val, bytes):
      ef = decode_fields(val)
      key_hash = get_bytes(ef, 1)
      if key_hash:
        entries.append(key_hash.hex())
  return {
    'number_of_entries': get_int(fields, 1),
    'entries': entries,
    'slot_mask': get_int(fields, 3),
  }


def parse_whitelist_entry_info(data: bytes) -> dict:
  """Parse a WhitelistEntryInfo message."""
  fields = decode_fields(data)
  result = {'slot': get_int(fields, 6), 'key_role': get_int(fields, 7)}
  pk_bytes = get_bytes(fields, 2)
  if pk_bytes:
    pk_fields = decode_fields(pk_bytes)
    result['public_key'] = get_bytes(pk_fields, 1)
  return result


def parse_action_status(data: bytes) -> dict:
  """Parse an ActionStatus response from infotainment."""
  fields = decode_fields(data)
  return {
    'result': get_int(fields, 1),
    'description': get_bytes(fields, 2),
  }
