#!/usr/bin/env python3
import asyncio
import re

import logging

import hashlib

from bleak import BleakClient, BleakScanner

from openpilot.common.params import Params

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("teslabled")

# Tesla BLE UUIDs
TESLA_SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e"
TESLA_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"
TESLA_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"
TESLA_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"

# Tesla advertises as S<16 hex chars of SHA1(VIN)>C
TESLA_BLE_NAME_RE = re.compile(r"^S[0-9a-f]{16}C$")

SCAN_DURATION = 5.0  # seconds
SCAN_INTERVAL = 10.0  # seconds between scans when not connected


async def scan_for_teslas():
  """Scan for Tesla BLE advertisements. Returns list of matching devices."""
  log.info("scanning for Tesla BLE devices...")
  devices = await BleakScanner.discover(timeout=SCAN_DURATION)
  teslas = [d for d in devices if d.name and TESLA_BLE_NAME_RE.match(d.name)]
  for t in teslas:
    log.info(f"found Tesla: {t.name} ({t.address})")
  return teslas


async def connect(device):
  """Connect to a Tesla and set up BLE notifications."""
  log.info(f"connecting to {device.name} ({device.address})...")
  async with BleakClient(device) as client:
    log.info(f"connected to {device.name}")

    # read protocol version
    version = await client.read_gatt_char(TESLA_VERSION_UUID)
    log.info(f"protocol version: {version.hex()}")

    # subscribe to vehicle responses
    def on_notify(_handle, data: bytearray):
      log.info(f"rx: {data.hex()}")

    await client.start_notify(TESLA_READ_UUID, on_notify)

    # TODO: send session info request and do ECDH key exchange
    log.info("session setup not yet implemented, holding connection...")

    # hold connection
    while client.is_connected:
      await asyncio.sleep(1.0)

  log.info(f"disconnected from {device.name}")


async def run():
  while True:
    teslas = await scan_for_teslas()
    if not teslas:
      log.info("no Tesla found, retrying...")
      await asyncio.sleep(SCAN_INTERVAL)
      continue

    # connect to target Tesla by VIN
    params = Params()
    vin = params.get("TeslaVIN", encoding="utf-8")
    if not vin:
      log.info("TeslaVIN param not set, retrying...")
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
  log.info("teslabled started")
  asyncio.run(run())


if __name__ == "__main__":
  main()
