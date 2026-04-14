#!/usr/bin/env python3
"""Tesla BLE daemon — manages BLE connection to a Tesla vehicle using the VCSEC protocol."""
import asyncio
import hashlib
import logging
import os
import re
import struct
import time

from bleak import BleakClient, BleakScanner

from openpilot.system.teslable.crypto import load_or_create_key, ecdh_shared_key, encrypt_gcm, key_id
from openpilot.system.teslable.proto import encode_field, decode_fields, get_field

TESLA_VIN_PATH = "/data/teslable/vin"
TESLA_KEY_PATH = "/data/teslable/key.pem"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("teslad")

# Tesla BLE UUIDs
TESLA_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"
TESLA_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"
TESLA_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"

TESLA_BLE_NAME_RE = re.compile(r"^S[0-9a-f]{16}C$")

SCAN_DURATION = 5.0
SCAN_INTERVAL = 10.0

# ── RKE actions ──

RKE_ACTION_UNLOCK = 0
RKE_ACTION_LOCK = 1
RKE_ACTION_OPEN_TRUNK = 2
RKE_ACTION_OPEN_FRUNK = 3
RKE_ACTION_OPEN_CHARGE_PORT = 4
RKE_ACTION_CLOSE_CHARGE_PORT = 5
RKE_ACTION_REMOTE_DRIVE = 20
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


# ── VCSEC message builders ──

def build_ephemeral_key_request(kid_bytes):
  key_id_msg = encode_field(1, kid_bytes)
  info_req = encode_field(1, 3) + encode_field(2, key_id_msg)
  unsigned_msg = encode_field(1, info_req)
  return encode_field(2, unsigned_msg)


def build_whitelist_request(public_key_bytes):
  pubkey_msg = encode_field(1, public_key_bytes)
  perm_change = encode_field(1, pubkey_msg) + encode_field(4, 2)
  metadata = encode_field(1, 7)
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
    result['vehicle_status'] = {
      'vehicle_lock_state': get_field(vs, 2),
      'vehicle_sleep_status': get_field(vs, 3),
      'user_presence': get_field(vs, 4),
    }

  return result


# ── Tesla session ──

class TeslaSession:
  def __init__(self, client, shared_key, kid_bytes, rx_queue):
    self.client = client
    self.shared_key = shared_key
    self.kid = kid_bytes
    self.rx_queue = rx_queue
    self.counter = int(time.time())

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
        payload = response[2:]
        parsed = parse_from_vcsec(payload)
        if parsed.get('command_status') is not None:
          return parsed
      except asyncio.TimeoutError:
        break
    return None

  async def unlock(self):
    log.info("unlocking...")
    await self.send_rke(RKE_ACTION_UNLOCK)
    return await self.wait_for_response()

  async def lock(self):
    log.info("locking...")
    await self.send_rke(RKE_ACTION_LOCK)
    return await self.wait_for_response()

  async def open_trunk(self):
    log.info("opening trunk...")
    await self.send_rke(RKE_ACTION_OPEN_TRUNK)
    return await self.wait_for_response()

  async def close_trunk(self):
    log.info("closing trunk...")
    await self.send_closure_move(rear_trunk=CLOSURE_MOVE_CLOSE)
    return await self.wait_for_response()

  async def open_frunk(self):
    log.info("opening frunk...")
    await self.send_rke(RKE_ACTION_OPEN_FRUNK)
    return await self.wait_for_response()

  async def open_charge_port(self):
    log.info("opening charge port...")
    await self.send_rke(RKE_ACTION_OPEN_CHARGE_PORT)
    return await self.wait_for_response()

  async def close_charge_port(self):
    log.info("closing charge port...")
    await self.send_rke(RKE_ACTION_CLOSE_CHARGE_PORT)
    return await self.wait_for_response()

  async def wake(self):
    log.info("waking vehicle...")
    await self.send_rke(RKE_ACTION_WAKE_VEHICLE)
    return await self.wait_for_response()


async def scan_for_teslas():
  log.info("scanning for Tesla BLE devices...")
  devices = await BleakScanner.discover(timeout=SCAN_DURATION)
  teslas = [d for d in devices if d.name and TESLA_BLE_NAME_RE.match(d.name)]
  for t in teslas:
    log.info(f"found Tesla: {t.name} ({t.address})")
  return teslas


async def establish_session(device):
  """Connect to a Tesla and return a TeslaSession, or None on failure."""
  log.info(f"connecting to {device.name} ({device.address})...")

  private_key, public_key_bytes = load_or_create_key(TESLA_KEY_PATH)
  kid = key_id(public_key_bytes)

  rx_queue = asyncio.Queue()

  client = BleakClient(device.address)
  await client.connect(timeout=15.0)
  log.info(f"connected to {device.name}")

  await client.start_notify(TESLA_READ_UUID, lambda _h, d: rx_queue.put_nowait(bytes(d)))
  await asyncio.sleep(0.5)
  while not rx_queue.empty():
    rx_queue.get_nowait()

  # request ephemeral key
  msg = build_ephemeral_key_request(kid)
  await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))

  try:
    response = await asyncio.wait_for(rx_queue.get(), timeout=5.0)
  except asyncio.TimeoutError:
    log.error("no response to ephemeral key request")
    await client.disconnect()
    return None

  parsed = parse_from_vcsec(response[2:])
  vehicle_pubkey = None
  if 'session_info' in parsed and parsed['session_info'].get('public_key'):
    vehicle_pubkey = parsed['session_info']['public_key']

  if vehicle_pubkey is None:
    log.error("key not on whitelist — run whitelist.py first")
    await client.disconnect()
    return None

  shared_key = ecdh_shared_key(private_key, vehicle_pubkey)
  log.info("session established")

  return TeslaSession(client, shared_key, kid, rx_queue)


async def run():
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
      log.info("no Tesla found, retrying...")
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    expected_name = "S" + hashlib.sha1(vin.encode()).hexdigest()[:16] + "C"
    target = next((t for t in teslas if t.name == expected_name), None)
    if target is None:
      log.info(f"target Tesla ({expected_name}) not found, retrying...")
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    try:
      session = await establish_session(target)
      if session is None:
        await asyncio.sleep(SCAN_INTERVAL)
        continue

      # hold connection
      while session.client.is_connected:
        await asyncio.sleep(1.0)

      log.info(f"disconnected from {target.name}")
    except Exception as e:
      log.error(f"connection failed: {e}")

    await asyncio.sleep(SCAN_INTERVAL)


def main():
  log.info("teslad started")
  asyncio.run(run())


if __name__ == "__main__":
  main()
