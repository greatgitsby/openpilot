#!/usr/bin/env python3
import asyncio
import re

import logging

from bleak import BleakScanner

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("teslabled")

# Tesla BLE service UUID
TESLA_SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e"

# Tesla advertises as S<16 hex chars of SHA1(VIN)>C
TESLA_BLE_NAME_RE = re.compile(r"^S[0-9a-f]{16}C$")

SCAN_DURATION = 5.0  # seconds
SCAN_INTERVAL = 10.0  # seconds between scans when not connected


async def scan_for_tesla():
  """Scan for Tesla BLE advertisements. Returns the first matching device or None."""
  log.info("teslabled: scanning for Tesla BLE devices...")
  devices = await BleakScanner.discover(timeout=SCAN_DURATION, service_uuids=[TESLA_SERVICE_UUID])
  for device in devices:
    if device.name and TESLA_BLE_NAME_RE.match(device.name):
      log.info(f"teslabled: found Tesla: {device.name} ({device.address})")
      return device
  return None


async def run():
  while True:
    device = await scan_for_tesla()
    if device is None:
      log.info("teslabled: no Tesla found, retrying...")
    else:
      # TODO: connect and establish session
      log.info(f"teslabled: ready to connect to {device.name}")
    await asyncio.sleep(SCAN_INTERVAL)


def main():
  log.info("teslabled started")
  asyncio.run(run())


if __name__ == "__main__":
  main()
