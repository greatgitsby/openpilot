#!/usr/bin/env python3
"""Standalone script to whitelist our BLE key with a Tesla.
Usage: python3 -m system.teslable.whitelist
Then tap your NFC key card on the center console when prompted."""
import asyncio
import hashlib
import logging
import struct
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(asctime)s %(message)s')
log = logging.getLogger("whitelist")

from bleak import BleakClient, BleakScanner

from openpilot.system.teslable.crypto import load_or_create_key, key_id
from openpilot.system.teslable.proto import encode_field, decode_fields, get_field
from openpilot.system.teslable.teslad import (
  TESLA_WRITE_UUID, TESLA_READ_UUID, TESLA_VIN_PATH, TESLA_KEY_PATH,
  TESLA_BLE_NAME_RE, ble_frame, build_whitelist_request, scan_for_teslas,
)


async def main():
  priv, pub = load_or_create_key(TESLA_KEY_PATH)
  kid = key_id(pub)
  log.info(f"key id: {kid.hex()}")

  try:
    with open(TESLA_VIN_PATH) as f:
      vin = f.read().strip()
  except FileNotFoundError:
    log.error(f"{TESLA_VIN_PATH} not found — write your VIN to that file first")
    return

  expected_name = "S" + hashlib.sha1(vin.encode()).hexdigest()[:16] + "C"
  log.info(f"looking for {expected_name}...")

  teslas = await scan_for_teslas()
  target = next((t for t in teslas if t.name == expected_name), None)
  if target is None:
    log.error("target Tesla not found")
    return

  log.info(f"connecting to {target.address}...")
  rx = asyncio.Queue()

  async with BleakClient(target.address, timeout=15.0) as client:
    log.info("connected")
    await client.start_notify(TESLA_READ_UUID, lambda _h, d: rx.put_nowait(bytes(d)))
    await asyncio.sleep(1)
    while not rx.empty():
      rx.get_nowait()

    wl_msg = build_whitelist_request(pub)
    log.info("sending whitelist request...")
    await client.write_gatt_char(TESLA_WRITE_UUID, ble_frame(wl_msg))
    log.info(">>> TAP YOUR NFC KEY CARD ON THE CENTER CONSOLE <<<")

    for i in range(60):
      await asyncio.sleep(1)
      while not rx.empty():
        data = rx.get_nowait()
        fields = decode_fields(data[2:])
        fnums = [f[0] for f in fields]
        if 4 in fnums:
          log.info(f"whitelist accepted!")
          return
      if i > 0 and i % 15 == 0:
        log.info(f"still waiting for key card tap... ({i}s)")

    log.info("timed out — key card was not tapped")


if __name__ == "__main__":
  asyncio.run(main())
