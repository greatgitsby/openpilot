#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from collections.abc import Generator
from typing import Optional

try:
  import serial  # type: ignore
except ImportError as exc:  # pragma: no cover - handled at runtime
  sys.stderr.write("pyserial is required (`pip install pyserial`)\n")
  raise SystemExit(1) from exc


DEFAULT_DEVICE = "/dev/ttyUSB3"
DEFAULT_BAUD = 115200
DEFAULT_TIMEOUT = 5.0
ISDR_AID = "A0000005591010FFFFFFFF8900001000"
ES10X_MSS = 120

STATE_LABELS = {0: "disabled", 1: "enabled", 255: "unknown"}
ICON_LABELS = {0: "jpeg", 1: "png", 255: "unknown"}
CLASS_LABELS = {0: "test", 1: "provisioning", 2: "operational", 255: "unknown"}


class AtClient:
  def __init__(self, device: str, baud: int, timeout: float, verbose: bool) -> None:
    self.ser = serial.Serial(device, baudrate=baud, timeout=timeout)
    self.verbose = verbose
    self.channel: Optional[str] = None
    self.ser.reset_input_buffer()

  def close(self) -> None:
    try:
      if self.channel:
        self.query(f"AT+CCHC={self.channel}")
        self.channel = None
    finally:
      self.ser.close()

  def send(self, cmd: str) -> None:
    if self.verbose:
      print(f">> {cmd}", file=sys.stderr)
    self.ser.write((cmd + "\r").encode("ascii"))

  def expect(self) -> list[str]:
    lines: list[str] = []
    while True:
      raw = self.ser.readline()
      if not raw:
        raise TimeoutError("AT command timed out")
      line = raw.decode(errors="ignore").strip()
      if not line:
        continue
      if self.verbose:
        print(f"<< {line}", file=sys.stderr)
      if line == "OK":
        return lines
      if line == "ERROR":
        raise RuntimeError("AT command failed")
      lines.append(line)

  def query(self, cmd: str) -> list[str]:
    self.send(cmd)
    return self.expect()

  def ensure_capabilities(self) -> None:
    self.query("AT")
    for command in ("AT+CCHO", "AT+CCHC", "AT+CGLA"):
      self.query(f"{command}=?")

  def open_isdr(self) -> None:
    lines = self.query(f'AT+CCHO="{ISDR_AID}"')
    for line in lines:
      if line.startswith("+CCHO:"):
        identifier = line.split(":", 1)[1].strip()
        if identifier:
          self.channel = identifier
          return
    raise RuntimeError("Failed to open ISD-R application (missing +CCHO response)")

  def send_apdu(self, apdu: bytes) -> tuple[bytes, int, int]:
    if not self.channel:
      raise RuntimeError("Logical channel is not open")
    payload = binascii.hexlify(apdu).decode("ascii").upper()
    cmd = f'AT+CGLA={self.channel},{len(apdu) * 2},"{payload}"'
    lines = self.query(cmd)
    for line in lines:
      if line.startswith("+CGLA:"):
        _, rest = line.split(":", 1)
        parts = rest.split(",", 1)
        if len(parts) != 2:
          break
        hex_data = parts[1].strip().strip('"')
        data = binascii.unhexlify(hex_data)
        if len(data) < 2:
          raise RuntimeError("Incomplete APDU response")
        return data[:-2], data[-2], data[-1]
    raise RuntimeError("Missing +CGLA response")


def build_command_apdu(chunk: bytes, is_last: bool, sequence: int) -> bytes:
  header = bytearray([0x80, 0xE2, 0x91 if is_last else 0x11, sequence & 0xFF, len(chunk)])
  return bytes(header + chunk)


def build_get_response(le: int) -> bytes:
  le_byte = le if le else 0
  return bytes([0x80, 0xC0, 0x00, 0x00, le_byte])


def es10x_command(client: AtClient, data: bytes) -> bytes:
  response = bytearray()
  sequence = 0
  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + ES10X_MSS]
    offset += len(chunk)
    apdu = build_command_apdu(chunk, offset == len(data), sequence)
    segment, sw1, sw2 = client.send_apdu(apdu)
    response.extend(segment)
    while True:
      if sw1 == 0x61:
        le = sw2
        segment, sw1, sw2 = client.send_apdu(build_get_response(le))
        response.extend(segment)
        continue
      if (sw1 & 0xF0) == 0x90:
        break
      raise RuntimeError(f"APDU failed with SW={sw1:02X}{sw2:02X}")
    sequence += 1
  return bytes(response)


def iter_tlv(data: bytes) -> Generator[tuple[int, bytes], None, None]:
  idx = 0
  length = len(data)
  while idx < length:
    tag = data[idx]
    idx += 1
    if tag & 0x1F == 0x1F:
      tag_value = tag
      while idx < length:
        next_byte = data[idx]
        idx += 1
        tag_value = (tag_value << 8) | next_byte
        if not (next_byte & 0x80):
          break
    else:
      tag_value = tag

    if idx >= length:
      raise ValueError("Invalid TLV: missing length")
    size = data[idx]
    idx += 1
    if size & 0x80:
      num_bytes = size & 0x7F
      if idx + num_bytes > length:
        raise ValueError("Invalid TLV length")
      size = int.from_bytes(data[idx : idx + num_bytes], "big")
      idx += num_bytes
    if idx + size > length:
      raise ValueError("Invalid TLV value")
    value = data[idx : idx + size]
    idx += size
    yield tag_value, value


def find_tag(data: bytes, target: int) -> Optional[bytes]:
  for tag, value in iter_tlv(data):
    if tag == target:
      return value
  return None


def tbcd_to_string(raw: bytes) -> str:
  digits: list[str] = []
  for byte in raw:
    low = byte & 0x0F
    high = (byte >> 4) & 0x0F
    if low <= 9:
      digits.append(str(low))
    if high <= 9 and high != 0x0F:
      digits.append(str(high))
  return "".join(digits)


def decode_profiles(blob: bytes) -> list[dict]:
  root = find_tag(blob, 0xBF2D)
  if root is None:
    raise RuntimeError("Missing ProfileInfoList (0xBF2D)")
  list_ok = find_tag(root, 0xA0)
  if list_ok is None:
    return []
  profiles: list[dict] = []
  for tag, value in iter_tlv(list_ok):
    if tag != 0xE3:
      continue
    profile: dict = {
      "iccid": None,
      "isdpAid": None,
      "profileState": None,
      "profileNickname": None,
      "serviceProviderName": None,
      "profileName": None,
      "iconType": None,
      "icon": None,
      "profileClass": None,
    }
    for item_tag, item_value in iter_tlv(value):
      if item_tag == 0x5A:
        profile["iccid"] = tbcd_to_string(item_value)
      elif item_tag == 0x4F:
        profile["isdpAid"] = item_value.hex().upper()
      elif item_tag == 0x9F70:
        state = int.from_bytes(item_value, "big")
        profile["profileState"] = STATE_LABELS.get(state, "unknown")
      elif item_tag == 0x90:
        profile["profileNickname"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x91:
        profile["serviceProviderName"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x92:
        profile["profileName"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x93:
        icon_type = int.from_bytes(item_value, "big")
        profile["iconType"] = ICON_LABELS.get(icon_type, "unknown")
      elif item_tag == 0x94:
        profile["icon"] = base64.b64encode(item_value).decode("ascii")
      elif item_tag == 0x95:
        pclass = int.from_bytes(item_value, "big")
        profile["profileClass"] = CLASS_LABELS.get(pclass, "unknown")
    profiles.append(profile)
  return profiles


def request_profile_info(client: AtClient) -> list[dict]:
  der_request = bytes.fromhex("BF2D00")
  payload = es10x_command(client, der_request)
  return decode_profiles(payload)


def build_cli() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Minimal AT-only lpac profile list clone")
  parser.add_argument("--device", default=DEFAULT_DEVICE, help=f"Serial device path (default: {DEFAULT_DEVICE})")
  parser.add_argument("--baud", type=int, default=DEFAULT_BAUD, help=f"Serial baud rate (default: {DEFAULT_BAUD})")
  parser.add_argument(
    "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Serial read timeout in seconds (default: {DEFAULT_TIMEOUT})"
  )
  parser.add_argument("--verbose", action="store_true", help="Print raw AT traffic to stderr")
  return parser


def main() -> None:
  args = build_cli().parse_args()
  client = AtClient(args.device, args.baud, args.timeout, args.verbose)
  try:
    client.ensure_capabilities()
    client.open_isdr()
    profiles = request_profile_info(client)
  finally:
    client.close()

  print(json.dumps(profiles, indent=2))


if __name__ == "__main__":
  main()
