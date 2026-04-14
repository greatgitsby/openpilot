#!/usr/bin/env python3
"""Standalone script to whitelist our BLE key with a Tesla."""
import asyncio
import struct

from bleak import BleakClient, BleakScanner

from openpilot.system.teslable.crypto import load_or_create_key, key_id
from openpilot.system.teslable.proto import encode_field, decode_fields, get_field

WRITE = "00000212-b2d1-43f0-9b88-960cebf8b91e"
READ  = "00000213-b2d1-43f0-9b88-960cebf8b91e"
ADDR  = "B0:D2:78:94:F3:48"


def frame(msg):
  return struct.pack(">H", len(msg)) + msg


async def main():
  priv, pub = load_or_create_key("/data/teslable/key.pem")
  kid = key_id(pub)
  print(f"key id: {kid.hex()}")

  print("scanning to warm bluez cache...")
  await BleakScanner.discover(timeout=5.0)

  print(f"connecting to {ADDR}...")
  rx = asyncio.Queue()

  async with BleakClient(ADDR, timeout=15.0) as client:
    print("connected")

    await client.start_notify(READ, lambda _h, d: rx.put_nowait(bytes(d)))
    await asyncio.sleep(1)
    while not rx.empty():
      rx.get_nowait()

    # build whitelist request
    pubkey_msg = encode_field(1, pub)
    perm_change = encode_field(1, pubkey_msg) + encode_field(4, 2)  # ROLE_OWNER
    metadata = encode_field(1, 7)  # ANDROID_DEVICE
    whitelist_op = encode_field(5, perm_change) + encode_field(6, metadata)
    unsigned_msg = encode_field(16, whitelist_op)
    signed_msg = encode_field(2, unsigned_msg) + encode_field(3, 2)  # PRESENT_KEY
    to_vcsec = encode_field(1, signed_msg)

    print("sending whitelist request...")
    await client.write_gatt_char(WRITE, frame(to_vcsec))
    print(">>> TAP YOUR KEY CARD ON CENTER CONSOLE NOW <<<")

    for i in range(60):
      await asyncio.sleep(1)
      while not rx.empty():
        data = rx.get_nowait()
        payload = data[2:]
        fields = decode_fields(payload)
        fnums = [f[0] for f in fields]

        if 4 in fnums:
          cs = get_field(fields, 4)
          print(f"  [{i}s] COMMAND STATUS: {data.hex()}")
        elif 2 in fnums:
          si = get_field(fields, 2)
          sif = decode_fields(si)
          ctr = get_field(sif, 2)
          pk = get_field(sif, 3)
          print(f"  [{i}s] SESSION INFO: counter={ctr} has_pubkey={pk is not None}")
          if ctr is not None:
            print("KEY WHITELISTED SUCCESSFULLY!")
            return
        elif 1 in fnums:
          print(f"  [{i}s] vehicle_status")

      if i > 0 and i % 15 == 0:
        print(f"  [{i}s] still waiting for key card tap...")

    print("timed out — key card was not tapped")


if __name__ == "__main__":
  asyncio.run(main())
