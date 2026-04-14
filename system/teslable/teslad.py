#!/usr/bin/env python3
"""Tesla BLE daemon — manages BLE connection to a Tesla vehicle using the VCSEC protocol."""
import asyncio
import hashlib
import logging
import os
import re
import struct

from bleak import BleakClient, BleakScanner

import time

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


def ble_frame(msg):
  """Prepend 2-byte big-endian length prefix."""
  return struct.pack('>H', len(msg)) + msg


# ── VCSEC message builders (all use ToVCSECMessage, NOT RoutableMessage) ──

def build_ephemeral_key_request(kid_bytes):
  """Request vehicle's ephemeral public key.
  ToVCSECMessage { unsignedMessage (field 2) {
    InformationRequest (field 1) {
      informationRequestType (field 1) = GET_EPHEMERAL_PUBLIC_KEY (3)
      keyId (field 2) { publicKeySHA1 (field 1) = <4 bytes> }
    }
  }}"""
  key_id_msg = encode_field(1, kid_bytes)  # KeyIdentifier.publicKeySHA1
  info_req = encode_field(1, 3) + encode_field(2, key_id_msg)  # type=3, keyId
  unsigned_msg = encode_field(1, info_req)  # UnsignedMessage.InformationRequest
  return encode_field(2, unsigned_msg)  # ToVCSECMessage.unsignedMessage


def build_whitelist_request(public_key_bytes):
  """Build a ToVCSECMessage to add our key to the whitelist.
  ToVCSECMessage { signedMessage (field 1) {
    protobufMessageAsBytes (field 2) = serialized UnsignedMessage
    signatureType (field 3) = SIGNATURE_TYPE_PRESENT_KEY (2)
  }}"""
  pubkey_msg = encode_field(1, public_key_bytes)  # PublicKey.PublicKeyRaw
  perm_change = encode_field(1, pubkey_msg) + encode_field(4, 2)  # key + keyRole=ROLE_OWNER
  metadata = encode_field(1, 7)  # keyFormFactor = KEY_FORM_FACTOR_ANDROID_DEVICE
  whitelist_op = encode_field(5, perm_change) + encode_field(6, metadata)
  unsigned_msg = encode_field(16, whitelist_op)  # UnsignedMessage.WhitelistOperation

  signed_msg = encode_field(2, unsigned_msg) + encode_field(3, 2)  # PRESENT_KEY
  return encode_field(1, signed_msg)  # ToVCSECMessage.signedMessage


def build_signed_command(shared_key, kid_bytes, counter, unsigned_msg_bytes):
  """Encrypt an UnsignedMessage with AES-GCM and wrap in ToVCSECMessage.signedMessage.

  The plaintext is a serialized ToVCSECMessage { unsignedMessage = <unsigned_msg> },
  NOT the raw UnsignedMessage bytes."""
  # wrap UnsignedMessage in ToVCSECMessage.unsignedMessage (field 2) before encrypting
  plaintext = encode_field(2, unsigned_msg_bytes)

  ciphertext, tag = encrypt_gcm(shared_key, counter, plaintext)

  signed_msg = b''
  signed_msg += encode_field(2, ciphertext)
  signed_msg += encode_field(3, 0)  # SIGNATURE_TYPE_AES_GCM
  signed_msg += encode_field(5, counter)
  signed_msg += encode_field(6, tag)
  signed_msg += encode_field(7, kid_bytes)

  return encode_field(1, signed_msg)  # ToVCSECMessage.signedMessage


# RKEAction_E values
RKE_ACTION_UNLOCK = 0
RKE_ACTION_LOCK = 1
RKE_ACTION_OPEN_TRUNK = 2
RKE_ACTION_OPEN_FRUNK = 3
RKE_ACTION_OPEN_CHARGE_PORT = 4
RKE_ACTION_CLOSE_CHARGE_PORT = 5


def build_rke_action(action):
  """Build UnsignedMessage { RKEAction (field 2) = action }"""
  return encode_field(2, action)


# ── VCSEC response parsers ──

def parse_from_vcsec(data):
  """Parse a FromVCSECMessage response.
  FromVCSECMessage {
    commandStatus (field 1)
    sessionInfo (field 2) {
      token (field 1)
      counter (field 2)
      publicKey (field 3) — 65-byte vehicle ephemeral key
    }
    whitelistInfo (field 3)
    ...
  }"""
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

  command_status_bytes = get_field(fields, 1)
  if command_status_bytes is not None:
    cs = decode_fields(command_status_bytes)
    result['command_status'] = {
      'operation_status': get_field(cs, 1),
      'signed_message_fault': get_field(cs, 2),
    }

  return result


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

  rx_queue = asyncio.Queue()

  async with BleakClient(device.address) as client:
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

    # request ephemeral key to check if we're whitelisted
    msg = build_ephemeral_key_request(kid)
    log.info("requesting vehicle ephemeral key...")
    await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))

    try:
      response = await asyncio.wait_for(rx_queue.get(), timeout=5.0)
    except asyncio.TimeoutError:
      log.error("no response to ephemeral key request")
      return

    payload = response[2:]  # strip length prefix
    parsed = parse_from_vcsec(payload)
    log.info(f"response: {parsed}")

    vehicle_pubkey = None
    if 'session_info' in parsed and parsed['session_info'].get('public_key'):
      vehicle_pubkey = parsed['session_info']['public_key']

    if vehicle_pubkey is None:
      # not whitelisted — send whitelist request and poll
      log.info("key not on whitelist — sending whitelist request")
      log.info(">>> TAP YOUR NFC KEY CARD ON THE CENTER CONSOLE <<<")

      wl_msg = build_whitelist_request(public_key_bytes)
      await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(wl_msg))

      # poll for ephemeral key every 2s until whitelisted or timeout
      for attempt in range(30):
        await asyncio.sleep(2.0)

        # drain and check for session info
        while not rx_queue.empty():
          resp = rx_queue.get_nowait()
          p = parse_from_vcsec(resp[2:])
          if 'session_info' in p and p['session_info'].get('public_key'):
            vehicle_pubkey = p['session_info']['public_key']
            break

        if vehicle_pubkey:
          break

        # re-request ephemeral key
        msg = build_ephemeral_key_request(kid)
        await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(msg))
        log.info(f"waiting for keycard tap... (attempt {attempt + 1}/30)")

      if vehicle_pubkey is None:
        log.error("whitelist timed out — key card not tapped")
        return

    log.info(f"vehicle public key: {vehicle_pubkey.hex()}")

    # derive shared key
    shared_key = ecdh_shared_key(private_key, vehicle_pubkey)
    log.info("shared key derived, session established!")

    # send open trunk command
    counter = int(time.time())
    unsigned_msg = build_rke_action(RKE_ACTION_OPEN_TRUNK)
    cmd = build_signed_command(shared_key, kid, counter, unsigned_msg)
    log.info(f"sending open trunk command (counter={counter})...")
    await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(cmd))

    # wait for response — drain unsolicited broadcasts to find actual response
    deadline = asyncio.get_event_loop().time() + 5.0
    while asyncio.get_event_loop().time() < deadline:
      try:
        response = await asyncio.wait_for(rx_queue.get(), timeout=2.0)
        payload = response[2:]
        log.info(f"trunk raw response: {response.hex()}")
        parsed = parse_from_vcsec(payload)
        log.info(f"trunk parsed: {parsed}")
        if parsed.get('command_status') is not None:
          break
      except asyncio.TimeoutError:
        break

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
