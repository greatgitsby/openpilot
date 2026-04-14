#!/usr/bin/env python3
import asyncio
import hashlib
import logging
import os
import re
import struct

from bleak import BleakClient, BleakScanner

from openpilot.system.teslable.crypto import load_or_create_key, ecdh_shared_key, derive_session_key, key_id
from openpilot.system.teslable.proto import encode_field, decode_fields, get_field

TESLA_VIN_PATH = "/data/teslable/vin"
TESLA_KEY_PATH = "/data/teslable/key.pem"

DOMAIN_VEHICLE_SECURITY = 2

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("teslad")

# Tesla BLE UUIDs
TESLA_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"
TESLA_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"
TESLA_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"

# Tesla advertises as S<16 hex chars of SHA1(VIN)>C
TESLA_BLE_NAME_RE = re.compile(r"^S[0-9a-f]{16}C$")

SCAN_DURATION = 5.0
SCAN_INTERVAL = 10.0

# SessionInfo status
SESSION_INFO_STATUS_OK = 0
SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST = 1


def build_session_info_request(public_key_bytes, domain, routing_address):
  """Build a RoutableMessage containing a SessionInfoRequest."""
  uuid = os.urandom(16)

  session_info_req = encode_field(1, public_key_bytes)
  to_dest = encode_field(1, domain)
  from_dest = encode_field(2, routing_address)

  msg = b''
  msg += encode_field(6, to_dest)
  msg += encode_field(7, from_dest)
  msg += encode_field(14, session_info_req)
  msg += encode_field(51, uuid)  # uuid is field 51

  return msg, uuid


def build_whitelist_request(public_key_bytes):
  """Build a ToVCSECMessage to add our key to the whitelist.
  This is NOT a RoutableMessage — it's sent raw over BLE.
  User must tap NFC key card on center console to approve."""

  # PublicKey { PublicKeyRaw (field 1) = <65 bytes> }
  pubkey_msg = encode_field(1, public_key_bytes)

  # PermissionChange: key (field 1) + keyRole (field 4) = ROLE_OWNER (2)
  perm_change = encode_field(1, pubkey_msg) + encode_field(4, 2)

  # KeyMetadata: keyFormFactor (field 1) = KEY_FORM_FACTOR_CLOUD_KEY (9)
  metadata = encode_field(1, 9)

  # WhitelistOperation: addKeyToWhitelistAndAddPermissions (field 5) + metadataForKey (field 6)
  whitelist_op = encode_field(5, perm_change) + encode_field(6, metadata)

  # UnsignedMessage: WhitelistOperation (field 16)
  unsigned_msg = encode_field(16, whitelist_op)

  # SignedMessage: protobufMessageAsBytes (field 2) + signatureType (field 3) = PRESENT_KEY (2)
  signed_msg = encode_field(2, unsigned_msg) + encode_field(3, 2)

  # ToVCSECMessage: signedMessage (field 1)
  to_vcsec = encode_field(1, signed_msg)

  return to_vcsec


def parse_session_info(data):
  """Parse a RoutableMessage containing SessionInfo. Returns dict or None."""
  fields = decode_fields(data)

  # session_info is field 15 (raw bytes)
  session_info_bytes = get_field(fields, 15)
  if session_info_bytes is None:
    return None

  si_fields = decode_fields(session_info_bytes)
  return {
    'counter': get_field(si_fields, 1),
    'public_key': get_field(si_fields, 2),
    'epoch': get_field(si_fields, 3),
    'clock_time': get_field(si_fields, 4),
    'status': get_field(si_fields, 5),
  }


def ble_frame(msg):
  """Prepend 2-byte big-endian length prefix."""
  return struct.pack('>H', len(msg)) + msg


async def scan_for_teslas():
  log.info("scanning for Tesla BLE devices...")
  devices = await BleakScanner.discover(timeout=SCAN_DURATION)
  teslas = [d for d in devices if d.name and TESLA_BLE_NAME_RE.match(d.name)]
  for t in teslas:
    log.info(f"found Tesla: {t.name} ({t.address})")
  return teslas


async def connect(device):
  log.info(f"connecting to {device.name} ({device.address})...")

  private_key, public_key_bytes = load_or_create_key(TESLA_KEY_PATH)
  kid = key_id(public_key_bytes)
  log.info(f"using key id: {kid.hex()}")

  routing_address = os.urandom(16)
  rx_queue = asyncio.Queue()

  async with BleakClient(device) as client:
    log.info(f"connected to {device.name}")

    version = await client.read_gatt_char(TESLA_VERSION_UUID)
    log.info(f"protocol version: {version.hex()}")

    def on_notify(_handle, data: bytearray):
      rx_queue.put_nowait(bytes(data))

    try:
      await client.start_notify(TESLA_READ_UUID, on_notify)
    except Exception as e:
      log.warning(f"start_notify failed ({e}), retrying...")
      return

    # drain unsolicited messages
    await asyncio.sleep(0.5)
    while not rx_queue.empty():
      rx_queue.get_nowait()

    # request session info
    msg, uuid = build_session_info_request(public_key_bytes, DOMAIN_VEHICLE_SECURITY, routing_address)
    log.info(f"sending session info request...")
    await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))

    try:
      response = await asyncio.wait_for(rx_queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
      log.error("no session info response")
      return

    payload = response[2:] if len(response) > 2 else response
    session_info = parse_session_info(payload)
    if session_info is None:
      log.error(f"failed to parse session info: {response.hex()}")
      return

    status = session_info.get('status')
    if status == SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST:
      log.info("key not on whitelist — sending whitelist request")
      log.info(">>> TAP YOUR NFC KEY CARD ON THE CENTER CONSOLE <<<")

      wl_msg = build_whitelist_request(public_key_bytes)
      await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(wl_msg))

      # wait for whitelist response (user needs to tap key card)
      try:
        wl_response = await asyncio.wait_for(rx_queue.get(), timeout=30.0)
        log.info(f"whitelist response: {wl_response.hex()}")
      except asyncio.TimeoutError:
        log.error("whitelist timed out — did you tap the key card?")
        return

      # retry session info after whitelisting
      await asyncio.sleep(1.0)
      msg, uuid = build_session_info_request(public_key_bytes, DOMAIN_VEHICLE_SECURITY, routing_address)
      log.info("retrying session info request after whitelist...")
      await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))

      try:
        response = await asyncio.wait_for(rx_queue.get(), timeout=5.0)
      except asyncio.TimeoutError:
        log.error("no session info response after whitelist")
        return

      payload = response[2:] if len(response) > 2 else response
      session_info = parse_session_info(payload)
      if session_info is None:
        log.error(f"failed to parse session info after whitelist: {response.hex()}")
        return

    if session_info.get('status', 0) != SESSION_INFO_STATUS_OK:
      log.error(f"session info status: {session_info.get('status')}")
      return

    vehicle_pubkey = session_info['public_key']
    epoch = session_info['epoch']
    clock_time = session_info['clock_time']
    counter = session_info['counter']

    log.info(f"vehicle public key: {vehicle_pubkey.hex()}")
    log.info(f"epoch: {epoch.hex()}")
    log.info(f"clock_time: {clock_time}")
    log.info(f"counter: {counter}")

    shared_key = ecdh_shared_key(private_key, vehicle_pubkey)
    log.info(f"shared key derived")

    session_info_key = derive_session_key(shared_key, "session info")
    command_key = derive_session_key(shared_key, "authenticated command")
    log.info("session established!")

    # hold connection
    while client.is_connected:
      while not rx_queue.empty():
        data = rx_queue.get_nowait()
        log.info(f"rx: {data.hex()}")
      await asyncio.sleep(1.0)

  log.info(f"disconnected from {device.name}")


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
      await connect(target)
    except Exception as e:
      log.error(f"connection failed: {e}")

    await asyncio.sleep(SCAN_INTERVAL)


def main():
  log.info("teslad started")
  asyncio.run(run())


if __name__ == "__main__":
  main()
