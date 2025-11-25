#!/usr/bin/env python3

import argparse
import base64
import binascii
import hashlib
import json
import sys
from collections.abc import Generator
from typing import Optional

import requests  # type: ignore

try:
  import serial  # type: ignore
except ImportError as exc:  # pragma: no cover - handled at runtime
  sys.stderr.write("pyserial is required (`pip install pyserial`)\n")
  raise SystemExit(1) from exc


DEFAULT_DEVICE = "/dev/ttyUSB3"
DEFAULT_BAUD = 9600
DEFAULT_TIMEOUT = 5.0
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
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


def find_tag_with_position(data: bytes, target: int) -> Optional[tuple[bytes, int, int]]:
  """Find tag and return (value, start_pos, end_pos)."""
  idx = 0
  length = len(data)
  while idx < length:
    start_pos = idx
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
      break
    size = data[idx]
    idx += 1
    if size & 0x80:
      num_bytes = size & 0x7F
      if idx + num_bytes > length:
        break
      size = int.from_bytes(data[idx : idx + num_bytes], "big")
      idx += num_bytes
    if idx + size > length:
      break
    value = data[idx : idx + size]
    end_pos = idx + size
    idx += size
    if tag_value == target:
      return value, start_pos, end_pos
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


def string_to_tbcd(s: str) -> bytes:
  """Convert a string of digits to TBCD (Telephony Binary Coded Decimal) format.

  TBCD encoding: each byte contains two digits, with the low nibble being the
  first digit and the high nibble being the second digit. If the string has
  an odd number of digits, the last byte's high nibble is set to 0xF (filler).
  """
  result = bytearray()
  digits = [int(c) for c in s if c.isdigit()]
  for i in range(0, len(digits), 2):
    if i + 1 < len(digits):
      # Two digits: low nibble = first digit, high nibble = second digit
      byte_value = digits[i] | (digits[i + 1] << 4)
    else:
      # Odd number of digits: low nibble = last digit, high nibble = 0xF
      byte_value = digits[i] | 0xF0
    result.append(byte_value)
  return bytes(result)


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
  return decode_profiles(es10x_command(client, bytes.fromhex("BF2D00")))


def es10b_get_euicc_challenge_r(client: AtClient) -> bytes:
  """Get eUICC challenge using GetEuiccDataRequest (tag 0xBF2E)."""
  # Empty request: tag + length 00
  request = bytes([0xBF, 0x2E, 0x00])
  response = es10x_command(client, request)

  # Parse response: BF2E [length] 80 [16] [challenge]
  # Reference finds 0xBF2E, then finds 0x80 inside it
  root = find_tag(response, 0xBF2E)
  if root is None:
    raise RuntimeError("Missing GetEuiccDataResponse (0xBF2E)")

  challenge = find_tag(root, 0x80)
  if challenge is None:
    raise RuntimeError("Missing challenge in response")

  return challenge


def es10b_remove_notification_from_list(client: AtClient, seq_number: int) -> None:
  """Remove notification from list using NotificationSentRequest (tag 0xBF30).

  Sends the ES10b NotificationSent command to mark a notification as processed.
  """
  # Build request: BF30 [length] 80 [seqNumber]
  seq_bytes = seq_number.to_bytes((seq_number.bit_length() + 7) // 8 or 1, "big")
  seq_tlv = encode_tlv(0x80, seq_bytes)

  # Build BF30 request
  request = encode_tlv(0xBF30, seq_tlv)

  response = es10x_command(client, request)

  # Parse response: BF30 [length] 80 [status]
  root = find_tag(response, 0xBF30)
  if root is None:
    raise RuntimeError("Invalid NotificationSentResponse: missing 0xBF30 tag")

  status = find_tag(root, 0x80)
  if status is None:
    raise RuntimeError("Invalid NotificationSentResponse: missing status (0x80)")

  status_code = int.from_bytes(status, "big")
  if status_code != 0:
    raise RuntimeError(f"RemoveNotificationFromList failed with status: 0x{status_code:02X}")


def es10b_get_euicc_info_r(client: AtClient) -> bytes:
  """Get eUICC info using GetEuiccInfo1Request (tag 0xBF20)."""
  # Empty request: tag + length 00
  request = bytes([0xBF, 0x20, 0x00])
  response = es10x_command(client, request)

  # Response should start with BF20 tag - return entire response including tag
  # Reference uses tmpnode.self.ptr and tmpnode.self.length which includes the tag
  if not response.startswith(bytes([0xBF, 0x20])):
    raise RuntimeError("Missing GetEuiccInfo1Response (0xBF20)")

  return response


def es10b_get_euicc_challenge_and_info(client: AtClient) -> tuple[bytes, bytes]:
  """Get eUICC challenge and info."""
  challenge = es10b_get_euicc_challenge_r(client)
  euicc_info = es10b_get_euicc_info_r(client)

  return challenge, euicc_info


def hex_to_gsmbcd(hex_str: str) -> bytes:
  """Convert hex string to GSM BCD format (like euicc_hexutil_gsmbcd2bin)."""
  result = bytearray()
  for i in range(0, len(hex_str), 2):
    if i + 1 < len(hex_str):
      byte_val = int(hex_str[i : i + 2], 16)
      result.append(byte_val)
    else:
      result.append(int(hex_str[i], 16) | 0xF0)
  return bytes(result)


def encode_tlv(tag: int, value: bytes) -> bytes:
  """Encode TLV with proper DER length encoding. Handles both single and two-byte tags."""
  value_len = len(value)

  # Handle two-byte tags (tags > 255, e.g., 0xBF2B, 0xBF30)
  if tag > 255:
    tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
  else:
    tag_bytes = bytes([tag])

  if value_len <= 127:
    return tag_bytes + bytes([value_len]) + value
  else:
    length_bytes = value_len.to_bytes((value_len.bit_length() + 7) // 8, "big")
    return tag_bytes + bytes([0x80 | len(length_bytes)]) + length_bytes + value


def build_authenticate_server_request(
  server_signed1: bytes, server_signature1: bytes, euicc_ci_pk_id: bytes, server_certificate: bytes,
  matching_id: Optional[str] = None, imei: Optional[str] = None
) -> bytes:
  """Build DER-encoded AuthenticateServer request (tag 0xBF38)."""
  device_capabilities = bytearray()
  if imei:
    imei_bytes = hex_to_gsmbcd(imei)
    device_capabilities.extend([0x82, len(imei_bytes)])
    device_capabilities.extend(imei_bytes)

  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = bytearray([0x80, len(tac)]) + tac
  if device_capabilities:
    device_info.extend([0xA1, len(device_capabilities)])
    device_info.extend(device_capabilities)
  else:
    device_info.extend([0xA1, 0x00])

  ctx_params = bytearray()
  if matching_id:
    matching_id_bytes = matching_id.encode("utf-8")
    ctx_params.extend([0x80, len(matching_id_bytes)])
    ctx_params.extend(matching_id_bytes)
  ctx_params.extend([0xA1, len(device_info)])
  ctx_params.extend(device_info)

  # Build main request: decoded bytes are already DER-encoded with their tags
  request_content = bytearray()
  request_content.extend(server_signed1)
  request_content.extend(server_signature1)
  request_content.extend(euicc_ci_pk_id)
  request_content.extend(server_certificate)
  request_content.extend(encode_tlv(0xA0, ctx_params))

  # Build BF38 tag with length
  request_length = len(request_content)
  if request_length <= 127:
    return bytes([0xBF, 0x38, request_length]) + request_content
  else:
    length_bytes = request_length.to_bytes((request_length.bit_length() + 7) // 8, "big")
    return bytes([0xBF, 0x38, 0x80 | len(length_bytes)]) + length_bytes + request_content


def es10b_authenticate_server_r(
  client: AtClient,
  b64_server_signed1: str,
  b64_server_signature1: str,
  b64_euicc_ci_pk_id: str,
  b64_server_certificate: str,
  matching_id: Optional[str] = None,
  imei: Optional[str] = None,
) -> tuple[bytes, str]:
  """Authenticate server using AuthenticateServerRequest (tag 0xBF38).

  Returns tuple of (transaction_id, b64_authenticate_server_response).
  """
  # Decode base64 inputs
  server_signed1 = base64.b64decode(b64_server_signed1)
  server_signature1 = base64.b64decode(b64_server_signature1)
  euicc_ci_pk_id = base64.b64decode(b64_euicc_ci_pk_id)
  server_certificate = base64.b64decode(b64_server_certificate)

  # Extract transactionId from serverSigned1 (tag 0x30, contains 0x80 [transactionId])
  server_signed1_root = find_tag(server_signed1, 0x30)
  if server_signed1_root is None:
    raise RuntimeError("Invalid serverSigned1: missing 0x30 tag")
  transaction_id = find_tag(server_signed1_root, 0x80)
  if transaction_id is None:
    raise RuntimeError("Invalid serverSigned1: missing transactionId (0x80)")

  request = build_authenticate_server_request(server_signed1, server_signature1, euicc_ci_pk_id, server_certificate, matching_id, imei)
  response = es10x_command(client, request)

  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse: expected tag 0xBF38")

  return base64.b64encode(response).decode("ascii")


def es10b_prepare_download_r(
  client: AtClient,
  b64_smdp_signed2: str,
  b64_smdp_signature2: str,
  b64_smdp_certificate: str,
  confirmation_code: Optional[str] = None,
) -> str:
  """Prepare download using PrepareDownloadRequest (tag 0xBF21).

  Returns base64-encoded PrepareDownloadResponse.
  """
  # Decode base64 inputs
  smdp_signed2 = base64.b64decode(b64_smdp_signed2)
  smdp_signature2 = base64.b64decode(b64_smdp_signature2)
  smdp_certificate = base64.b64decode(b64_smdp_certificate)

  # Find inner structures (they should already have their tags)
  smdp_signed2_root = find_tag(smdp_signed2, 0x30)
  if smdp_signed2_root is None:
    raise RuntimeError("Invalid smdpSigned2: missing 0x30 tag")

  # Extract transactionId and ccRequiredFlag from smdpSigned2
  transaction_id = find_tag(smdp_signed2_root, 0x80)
  if transaction_id is None:
    raise RuntimeError("Invalid smdpSigned2: missing transactionId (0x80)")

  cc_required_flag = find_tag(smdp_signed2_root, 0x01)
  if cc_required_flag is None:
    raise RuntimeError("Invalid smdpSigned2: missing ccRequiredFlag (0x01)")

  cc_required = int.from_bytes(cc_required_flag, "big") != 0

  # Build request: BF21 [smdpSigned2] [smdpSignature2] [hashCc?] [smdpCertificate]
  request_content = bytearray()
  request_content.extend(smdp_signed2)
  request_content.extend(smdp_signature2)

  if cc_required:
    if not confirmation_code:
      raise RuntimeError("Confirmation code required but not provided")

    # Compute hashCc: SHA256(SHA256(confirmationCode) + transactionId)
    hash1 = hashlib.sha256(confirmation_code.encode("utf-8")).digest()
    hash2 = hashlib.sha256(hash1 + transaction_id).digest()
    request_content.extend(encode_tlv(0x04, hash2))

  request_content.extend(smdp_certificate)

  # Build BF21 tag with length
  request_length = len(request_content)
  if request_length <= 127:
    request = bytes([0xBF, 0x21, request_length]) + request_content
  else:
    length_bytes = request_length.to_bytes((request_length.bit_length() + 7) // 8, "big")
    request = bytes([0xBF, 0x21, 0x80 | len(length_bytes)]) + length_bytes + request_content

  response = es10x_command(client, request)

  if not response.startswith(bytes([0xBF, 0x21])):
    raise RuntimeError("Invalid PrepareDownloadResponse: expected tag 0xBF21")

  return base64.b64encode(response).decode("ascii")


def parse_tlv_with_positions(data: bytes, start_idx: int = 0) -> Generator[tuple[int, bytes, int, int], None, None]:
  """Parse TLV and yield (tag, value, start_pos, end_pos)."""
  idx = start_idx
  length = len(data)
  while idx < length:
    start_pos = idx
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
      break
    size = data[idx]
    idx += 1
    if size & 0x80:
      num_bytes = size & 0x7F
      if idx + num_bytes > length:
        break
      size = int.from_bytes(data[idx : idx + num_bytes], "big")
      idx += num_bytes
    if idx + size > length:
      break
    value = data[idx : idx + size]
    end_pos = idx + size
    idx += size
    yield tag_value, value, start_pos, end_pos


def es10b_load_bound_profile_package_r(client: AtClient, b64_bound_profile_package: str) -> dict:
  """Load bound profile package onto eUICC.

  Returns a dictionary with:
    - seqNumber: Sequence number from notification metadata
    - success: True if installation succeeded
    - bppCommandId: BPP command ID if error occurred
    - errorReason: Error reason if error occurred
  """
  bpp = base64.b64decode(b64_bound_profile_package)

  # Verify it starts with 0xBF36 (BoundProfilePackage)
  if not bpp.startswith(bytes([0xBF, 0x36])):
    raise RuntimeError("Invalid BoundProfilePackage: expected tag 0xBF36")

  # Parse the structure to extract chunks
  chunks = []
  bpp_root_value = None
  bpp_root_start = 0
  bpp_value_start = 0  # Position where BF36 value starts (after tag and length)

  # Find BF36 root
  for tag, value, start, end in parse_tlv_with_positions(bpp):
    if tag == 0xBF36:
      bpp_root_value = value
      bpp_root_start = start
      # Calculate where the value starts (after tag and length)
      bf36_data = bpp[start:end]
      tag_len = 2  # BF36 is a two-byte tag
      length_byte = bf36_data[tag_len]
      if length_byte & 0x80:
        length_len = 1 + (length_byte & 0x7F)
      else:
        length_len = 1
      bpp_value_start = start + tag_len + length_len
      break

  if bpp_root_value is None:
    raise RuntimeError("Invalid BoundProfilePackage: missing 0xBF36 tag")

  # Chunk 1: From start of BF36 to end of BF23
  bf23_end = bpp_root_start
  for tag, _value, _start, end in parse_tlv_with_positions(bpp_root_value):
    if tag == 0xBF23:
      # Calculate absolute position: value_start + relative_end
      bf23_end = bpp_value_start + end
      break
  if bf23_end > bpp_root_start:
    chunk1 = bpp[bpp_root_start : bf23_end]
    chunks.append(chunk1)

  # Chunk 2: 0xA0 tag
  for tag, _value, start, end in parse_tlv_with_positions(bpp_root_value):
    if tag == 0xA0:
      chunk2 = bpp[bpp_value_start + start : bpp_value_start + end]
      chunks.append(chunk2)
      break

  # Chunk 3: Part of 0xA1 (up to value start)
  # Chunk 4: Children of 0xA1
  for tag, value, start, end in parse_tlv_with_positions(bpp_root_value):
    if tag == 0xA1:
      # Find where value starts (after tag and length)
      a1_data = bpp_root_value[start:end]
      tag_len = 1
      if a1_data[0] & 0x1F == 0x1F:
        tag_len = 2
      length_byte = a1_data[tag_len]
      if length_byte & 0x80:
        length_len = 1 + (length_byte & 0x7F)
      else:
        length_len = 1
      value_start_offset = tag_len + length_len
      chunk3 = bpp[bpp_value_start + start : bpp_value_start + start + value_start_offset]
      chunks.append(chunk3)

      # Children of 0xA1
      for child_tag, child_value in iter_tlv(value):
        child_chunk = encode_tlv(child_tag, child_value)
        chunks.append(child_chunk)
      break

  # Chunk 5: Optional 0xA2
  for tag, _value, start, end in parse_tlv_with_positions(bpp_root_value):
    if tag == 0xA2:
      chunk5 = bpp[bpp_value_start + start : bpp_value_start + end]
      chunks.append(chunk5)
      break

  # Chunk 6: Part of 0xA3 (up to value start)
  # Chunk 7: Children of 0xA3
  for tag, value, start, end in parse_tlv_with_positions(bpp_root_value):
    if tag == 0xA3:
      # Find where value starts
      a3_data = bpp_root_value[start:end]
      tag_len = 1
      if a3_data[0] & 0x1F == 0x1F:
        tag_len = 2
      length_byte = a3_data[tag_len]
      if length_byte & 0x80:
        length_len = 1 + (length_byte & 0x7F)
      else:
        length_len = 1
      value_start_offset = tag_len + length_len
      chunk6 = bpp[bpp_value_start + start : bpp_value_start + start + value_start_offset]
      chunks.append(chunk6)

      # Children of 0xA3
      for child_tag, child_value in iter_tlv(value):
        child_chunk = encode_tlv(child_tag, child_value)
        chunks.append(child_chunk)
      break

  # Send chunks and parse responses
  result = {"seqNumber": 0, "success": False, "bppCommandId": None, "errorReason": None}

  for chunk in chunks:
    response = es10x_command(client, chunk)

    # Parse response if present (tag 0xBF37 = ProfileInstallationResult)
    if response and len(response) > 0:
      root = find_tag(response, 0xBF37)
      if root:
        # Find ProfileInstallationResultData (0xBF27)
        result_data = find_tag(root, 0xBF27)
        if result_data:
          # Find NotificationMetadata (0xBF2F)
          notif_meta = find_tag(result_data, 0xBF2F)
          if notif_meta:
            seq_num = find_tag(notif_meta, 0x80)
            if seq_num:
              result["seqNumber"] = int.from_bytes(seq_num, "big")

          # Find finalResult (0xA2)
          final_result = find_tag(result_data, 0xA2)
          if final_result:
            # Check if it's SuccessResult (0xA0) or ErrorResult (0xA1)
            for tag, value in iter_tlv(final_result):
              if tag == 0xA0:
                result["success"] = True
              elif tag == 0xA1:
                # ErrorResult: extract bppCommandId (0x80) and errorReason (0x81)
                bpp_cmd_id = find_tag(value, 0x80)
                if bpp_cmd_id:
                  result["bppCommandId"] = int.from_bytes(bpp_cmd_id, "big")
                error_reason = find_tag(value, 0x81)
                if error_reason:
                  result["errorReason"] = int.from_bytes(error_reason, "big")

  if not result["success"] and result["errorReason"] is not None:
    raise RuntimeError(f"Profile installation failed: bppCommandId={result['bppCommandId']}, errorReason={result['errorReason']}")

  return result


def build_enable_profile_request(iccid: str) -> bytes:
  """Build DER-encoded EnableProfile request with ICCID.

  Structure: BF31 (EnableProfile) containing 5A (ICCID) with TBCD-encoded ICCID value.
  """
  iccid_tbcd = string_to_tbcd(iccid)
  # Build TLV structure: BF31 [length] A0 [length] 5A [iccid_length] [iccid_bytes]
  # BF31 = EnableProfile tag
  # A0 = Context tag for EnableProfileRequest
  # 5A = ICCID tag
  a0_content = bytearray([0x5A, len(iccid_tbcd)]) + iccid_tbcd
  bf31_content = bytearray([0xA0, len(a0_content)]) + a0_content
  bf31_length = len(bf31_content)
  # Handle length encoding: if length > 127, use multi-byte encoding
  if bf31_length <= 127:
    return bytes([0xBF, 0x31, bf31_length]) + bf31_content
  else:
    # Multi-byte length encoding (not expected for ICCID, but handle it)
    length_bytes = bf31_length.to_bytes((bf31_length.bit_length() + 7) // 8, "big")
    return bytes([0xBF, 0x31, 0x80 | len(length_bytes)]) + length_bytes + bf31_content


def build_disable_profile_request(iccid: str) -> bytes:
  """Build DER-encoded DisableProfile request with ICCID.

  Structure: BF32 (DisableProfile) containing 5A (ICCID) with TBCD-encoded ICCID value.
  """
  iccid_tbcd = string_to_tbcd(iccid)
  # Build TLV structure: BF32 [length] A0 [length] 5A [iccid_length] [iccid_bytes]
  # BF32 = DisableProfile tag
  # A0 = Context tag for DisableProfileRequest
  # 5A = ICCID tag
  a0_content = bytearray([0x5A, len(iccid_tbcd)]) + iccid_tbcd
  bf32_content = bytearray([0xA0, len(a0_content)]) + a0_content
  bf32_length = len(bf32_content)
  # Handle length encoding: if length > 127, use multi-byte encoding
  if bf32_length <= 127:
    return bytes([0xBF, 0x32, bf32_length]) + bf32_content
  else:
    # Multi-byte length encoding (not expected for ICCID, but handle it)
    length_bytes = bf32_length.to_bytes((bf32_length.bit_length() + 7) // 8, "big")
    return bytes([0xBF, 0x32, 0x80 | len(length_bytes)]) + length_bytes + bf32_content


def enable_profile(client: AtClient, iccid: str) -> None:
  """Enable an eSIM profile by ICCID.

  Sends the ES10c EnableProfile command and verifies the response.
  """
  der_request = build_enable_profile_request(iccid)
  payload = es10x_command(client, der_request)

  # Parse response: expect BF31 (EnableProfileResponse) with status
  # Response structure: BF31 [length] A0 [length] [status]
  # Status 0x00 = success, other values = error
  # According to the manual, response is BF310000 9000 for success
  root = find_tag(payload, 0xBF31)
  if root is None:
    raise RuntimeError("Missing EnableProfileResponse (0xBF31)")

  # Find the status in the response
  # The response should contain status information
  a0_content = find_tag(root, 0x80)
  if a0_content is None:
    raise RuntimeError('Missing status in EnableProfileResponse')
  code = a0_content[0]
  if code == 0x01:
    raise RuntimeError(f'profile {iccid} not found')
  elif code == 0x02:
    print(f'profile {iccid} already enabled')
  elif code != 0x00:
    raise RuntimeError(f'EnableProfile failed with status 0x{a0_content[0]:02X}')


def disable_profile(client: AtClient, iccid: str) -> None:
  """Disable an eSIM profile by ICCID.

  Sends the ES10c DisableProfile command and verifies the response.
  """
  der_request = build_disable_profile_request(iccid)
  payload = es10x_command(client, der_request)

  # Parse response: expect BF32 (DisableProfileResponse) with status
  # Response structure: BF32 [length] A0 [length] [status]
  # Status 0x00 = success, other values = error
  root = find_tag(payload, 0xBF32)
  if root is None:
    raise RuntimeError("Missing DisableProfileResponse (0xBF32)")

  # Find the status in the response
  # The response should contain status information
  a0_content = find_tag(root, 0x80)
  if a0_content is None:
    raise RuntimeError('Missing status in DisableProfileResponse')
  code = a0_content[0]
  if code == 0x01:
    raise RuntimeError(f'profile {iccid} not found')
  elif code == 0x02:
    print(f'profile {iccid} already disabled')
  elif code != 0x00:
    raise RuntimeError(f'DisableProfile failed with status 0x{code:02X}')


def build_set_nickname_request(iccid: str, nickname: str) -> bytes:
  """Build DER-encoded SetNickname request with ICCID and nickname.

  Structure: BF29 (SetNickname) containing A0 (SetNicknameRequest) with:
  - 5A (ICCID) with TBCD-encoded ICCID value
  - 90 (ProfileNickname) with UTF-8 encoded nickname string

  According to SGP.22 specification, nickname is UTF8String with size 0 to 64.
  """
  iccid_tbcd = string_to_tbcd(iccid)
  nickname_bytes = nickname.encode("utf-8")

  # Validate nickname length (0 to 64 bytes per SGP.22)
  if len(nickname_bytes) > 64:
    raise ValueError("Profile nickname must be 64 bytes or less (UTF-8 encoded)")

  # Build TLV structure: BF29 [length] A0 [length] 5A [iccid_length] [iccid_bytes] 90 [nickname_length] [nickname_bytes]
  # BF29 = SetNickname tag
  # A0 = Context tag for SetNicknameRequest
  # 5A = ICCID tag
  # 90 = ProfileNickname tag
  bf29_content = bytearray([0x5A, len(iccid_tbcd)]) + iccid_tbcd
  bf29_content.extend([0x90, len(nickname_bytes)])
  bf29_content.extend(nickname_bytes)

  bf29_length = len(bf29_content)

  # Handle length encoding: if length > 127, use multi-byte encoding
  if bf29_length <= 127:
    return bytes([0xBF, 0x29, bf29_length]) + bf29_content
  else:
    # Multi-byte length encoding
    length_bytes = bf29_length.to_bytes((bf29_length.bit_length() + 7) // 8, "big")
    return bytes([0xBF, 0x29, 0x80 | len(length_bytes)]) + length_bytes + bf29_content


def set_profile_nickname(client: AtClient, iccid: str, nickname: str) -> None:
  """Set the nickname for an eSIM profile by ICCID.

  Sends the ES10c SetNickname command and verifies the response.
  According to SGP.22 specification section 5.7.21.
  """
  der_request = build_set_nickname_request(iccid, nickname)
  payload = es10x_command(client, der_request)

  # Parse response: expect BF29 (SetNicknameResponse) with status
  # Response structure: BF29 [length] A0 [length] [status]
  # Status 0x00 = success, other values = error
  root = find_tag(payload, 0xBF29)
  if root is None:
    raise RuntimeError("Missing SetNicknameResponse (0xBF29)")

  # Find the status in the response
  # The response should contain status information
  a0_content = find_tag(root, 0x80)
  if a0_content is None:
    raise RuntimeError('Missing status in SetNicknameResponse')
  code = a0_content[0]
  if code == 0x01:
    raise RuntimeError(f'profile {iccid} not found')
  elif code != 0x00:
    raise RuntimeError(f'SetNickname failed with status 0x{code:02X}')


def build_list_notifications_request() -> bytes:
  """Build DER-encoded ListNotificationRequest (tag 0xBF28).

  Structure: BF28 [length] (empty - no content)
  According to lpac reference, the request is just the tag with length 0.
  """
  # Empty request: just tag BF28 with length 0
  return bytes([0xBF, 0x28, 0x00])


def build_retrieve_notifications_list_request(seq_number: int) -> bytes:
  """Build DER-encoded RetrieveNotificationsListRequest (tag 0xBF2B).

  Structure: BF2B [length] A0 [length] 80 [seqNumber]
  BF2B = RetrieveNotificationsListRequest tag
  A0 = searchCriteria
  80 = seqNumber
  """
  # Encode seqNumber
  seq_bytes = seq_number.to_bytes((seq_number.bit_length() + 7) // 8 or 1, "big")
  seq_tlv = encode_tlv(0x80, seq_bytes)

  # Build A0 (searchCriteria) containing seqNumber
  a0_content = seq_tlv
  a0_tlv = encode_tlv(0xA0, a0_content)

  # Build BF2B request
  request = encode_tlv(0xBF2B, a0_tlv)
  return request


def decode_notification_metadata_list(data: bytes) -> list[dict]:
  """Parse NotificationMetadataList from ListNotificationResponse (tag 0xBF28).

  Response structure: BF28 [length] A0 [length] [NotificationMetadataList]
  NotificationMetadataList is a SEQUENCE OF NotificationMetadata (tag 0xBF2F).
  According to lpac reference implementation.
  """
  root = find_tag(data, 0xBF28)
  if root is None:
    raise RuntimeError("Missing ListNotificationResponse (0xBF28)")

  # Find NotificationMetadataList (tag A0)
  metadata_list_data = find_tag(root, 0xA0)
  if metadata_list_data is None:
    # No notifications available
    return []

  notifications: list[dict] = []
  # Iterate through NotificationMetadata items (tag 0xBF2F)
  for tag, value in iter_tlv(metadata_list_data):
    if tag == 0xBF2F:
      notification = decode_notification_metadata(value)
      if notification:
        notifications.append(notification)

  return notifications


def decode_notification_metadata(metadata_data: bytes) -> Optional[dict]:
  """Parse individual NotificationMetadata TLV structure (tag 0xBF2F).

  Extracts sequence number, profile management operation, notification address, and ICCID.
  NotificationMetadata structure contains:
  - 0x80: seqNumber (integer) - required
  - 0x81: profileManagementOperation (bitstring) - required (checks value[1])
  - 0x0C: notificationAddress (UTF8String) - required
  - 0x5A: ICCID (TBCD) - optional
  """
  notification: dict = {
    "seqNumber": None,
    "profileManagementOperation": None,
    "notificationAddress": None,
    "iccid": None,
  }

  for tag, value in iter_tlv(metadata_data):
    if tag == 0x80:  # seqNumber
      if len(value) > 0:
        notification["seqNumber"] = int.from_bytes(value, "big")
    elif tag == 0x81:  # profileManagementOperation (bitstring)
      # Reference checks value[1] for the operation type
      if len(value) >= 2:
        op_value = value[1]
        # Map operation values (from reference)
        if op_value in (1, 2, 3, 4):  # INSTALL, ENABLE, DISABLE, DELETE
          notification["profileManagementOperation"] = op_value
        else:
          notification["profileManagementOperation"] = 255  # UNDEFINED
    elif tag == 0x0C:  # notificationAddress (UTF8String)
      notification["notificationAddress"] = value.decode("utf-8", errors="ignore")
    elif tag == 0x5A:  # ICCID (optional, TBCD format)
      notification["iccid"] = tbcd_to_string(value)

  # Only return notification if it has required fields
  if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"] is not None:
    return notification
  return None


def list_notifications(client: AtClient) -> list[dict]:
  """Retrieve notifications stored on the eUICC via ListNotificationRequest (tag 0xBF28).

  Sends the ES10b ListNotification command and parses the response.
  Returns a list of notification metadata dictionaries.
  According to lpac reference implementation.
  """
  der_request = build_list_notifications_request()
  payload = es10x_command(client, der_request)

  # Parse and return the notification metadata list
  return decode_notification_metadata_list(payload)


def es9p_handle_notification_r(smdp_address: str, b64_pending_notification: str) -> None:
  """Handle notification by sending it to SM-DP+ server."""
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/handleNotification"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  payload = {"pendingNotification": b64_pending_notification}

  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  data = resp.json()

  # Check for errors in response header
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      status_data = status.get("statusCodeData", {})
      reason = status_data.get("reasonCode", "unknown")
      subject = status_data.get("subjectCode", "unknown")
      message = status_data.get("message", "unknown")
      raise RuntimeError(f"HandleNotification failed: {reason}/{subject} - {message}")


def retrieve_notifications_list(client: AtClient, seq_number: int) -> dict:
  """Retrieve a specific notification by sequence number using RetrieveNotificationsListRequest (tag 0xBF2B).

  Returns a dictionary with:
    - notificationAddress: Notification address (URL)
    - b64_PendingNotification: Base64-encoded pending notification
  """
  der_request = build_retrieve_notifications_list_request(seq_number)
  response = es10x_command(client, der_request)

  # Parse response: BF2B [length] A0 [length] [PendingNotification]
  root = find_tag(response, 0xBF2B)
  if root is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse: missing 0xBF2B tag")

  a0_content = find_tag(root, 0xA0)
  if a0_content is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse: missing 0xA0 tag")

  # Find PendingNotification (can be 0xBF37 or 0x30)
  pending_notif = None
  pending_notif_tag = None
  for tag, value in iter_tlv(a0_content):
    if tag == 0xBF37 or tag == 0x30:
      pending_notif = value
      pending_notif_tag = tag
      break

  if pending_notif is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse: missing PendingNotification")

  # Find NotificationMetadata (0xBF2F)
  notif_meta = None
  if pending_notif_tag == 0xBF37:
    # profileInstallationResult: find BF27, then BF2F
    result_data = find_tag(pending_notif, 0xBF27)
    if result_data:
      notif_meta = find_tag(result_data, 0xBF2F)
  elif pending_notif_tag == 0x30:
    # otherSignedNotification: find BF2F directly
    notif_meta = find_tag(pending_notif, 0xBF2F)

  if notif_meta is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse: missing NotificationMetadata")

  # Extract notificationAddress (0x0C)
  notification_address = find_tag(notif_meta, 0x0C)
  if notification_address is None:
    raise RuntimeError("Invalid NotificationMetadata: missing notificationAddress (0x0C)")

  # Get the full PendingNotification bytes (need to find it in the response)
  # For now, we'll encode the value we found
  b64_pending_notif = base64.b64encode(pending_notif).decode("ascii")

  return {
    "notificationAddress": notification_address.decode("utf-8", errors="ignore"),
    "b64_PendingNotification": b64_pending_notif,
  }


def process_notifications(client: AtClient) -> None:
  """Process all notifications: retrieve, send to SM-DP+, and remove from eUICC."""
  notifications = list_notifications(client)

  if not notifications:
    print("No notifications to process", file=sys.stderr)
    return

  print(f"Found {len(notifications)} notification(s) to process", file=sys.stderr)

  for notification in notifications:
    seq_number = notification["seqNumber"]
    smdp_address = notification["notificationAddress"]

    if not seq_number or not smdp_address:
      print(f"Skipping invalid notification: {notification}", file=sys.stderr)
      continue

    print(f"Processing notification seqNumber={seq_number}, address={smdp_address}", file=sys.stderr)

    try:
      notif_data = retrieve_notifications_list(client, seq_number)
      es9p_handle_notification_r(smdp_address, notif_data["b64_PendingNotification"])
      es10b_remove_notification_from_list(client, seq_number)
      print(f"Notification {seq_number} processed successfully", file=sys.stderr)
    except Exception as e:
      print(f"Failed to process notification {seq_number}: {e}", file=sys.stderr)


def parse_lpa_activation_code(activation_code: str) -> dict[str, str]:
  """Parse LPA activation code: LPA:<version>$<smdp-address>$<activation-code>"""
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def base64_trim(s: str) -> str:
  """Remove whitespace from base64 string."""
  return "".join(c for c in s if c not in "\n\r \t")


def es9p_initiate_authentication_r(smdp_address: str, b64_euicc_challenge: str, b64_euicc_info_1: str) -> dict:
  """Initiate authentication with SM-DP+ server."""
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/initiateAuthentication"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  payload = {"smdpAddress": smdp_address, "euiccChallenge": b64_euicc_challenge, "euiccInfo1": b64_euicc_info_1}

  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  data = resp.json()

  # Check for errors in response header
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      status_data = status.get("statusCodeData", {})
      reason = status_data.get("reasonCode", "unknown")
      subject = status_data.get("subjectCode", "unknown")
      message = status_data.get("message", "unknown")
      raise RuntimeError(f"Authentication failed: {reason}/{subject} - {message}")

  return {
    "transactionId": base64_trim(data.get("transactionId", "")),
    "serverSigned1": base64_trim(data.get("serverSigned1", "")),
    "serverSignature1": base64_trim(data.get("serverSignature1", "")),
    "euiccCiPKIdToBeUsed": base64_trim(data.get("euiccCiPKIdToBeUsed", "")),
    "serverCertificate": base64_trim(data.get("serverCertificate", "")),
  }


def es9p_authenticate_client_r(smdp_address: str, transaction_id: str, b64_authenticate_server_response: str) -> dict:
  """Authenticate client with SM-DP+ server."""
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/authenticateClient"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  payload = {"transactionId": transaction_id, "authenticateServerResponse": b64_authenticate_server_response}

  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  data = resp.json()

  # Check for errors in response header
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      status_data = status.get("statusCodeData", {})
      reason = status_data.get("reasonCode", "unknown")
      subject = status_data.get("subjectCode", "unknown")
      message = status_data.get("message", "unknown")
      raise RuntimeError(f"Authentication failed: {reason}/{subject} - {message}")

  return {
    "profileMetadata": base64_trim(data.get("profileMetadata", "")),
    "smdpSigned2": base64_trim(data.get("smdpSigned2", "")),
    "smdpSignature2": base64_trim(data.get("smdpSignature2", "")),
    "smdpCertificate": base64_trim(data.get("smdpCertificate", "")),
  }


def es9p_get_bound_profile_package_r(smdp_address: str, transaction_id: str, b64_prepare_download_response: str) -> str:
  """Get bound profile package from SM-DP+ server."""
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/getBoundProfilePackage"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  payload = {"transactionId": transaction_id, "prepareDownloadResponse": b64_prepare_download_response}

  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  data = resp.json()

  # Check for errors in response header
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      status_data = status.get("statusCodeData", {})
      reason = status_data.get("reasonCode", "unknown")
      subject = status_data.get("subjectCode", "unknown")
      message = status_data.get("message", "unknown")
      raise RuntimeError(f"GetBoundProfilePackage failed: {reason}/{subject} - {message}")

  return base64_trim(data.get("boundProfilePackage", ""))


def es8p_metadata_parse(b64_metadata: str) -> dict:
  """Parse profileMetadata (StoreMetadataRequest, tag 0xBF25) from base64 string.

  Returns a dictionary with parsed metadata fields:
    - iccid: ICCID string
    - serviceProviderName: Service provider name
    - profileName: Profile name
    - iconType: Icon type ("jpeg", "png", "unknown", or None)
    - icon: Base64-encoded icon data
    - profileClass: Profile class ("test", "provisioning", "operational", "unknown", or None)
  """
  metadata = base64.b64decode(b64_metadata)

  # Find the 0xBF25 tag (StoreMetadataRequest)
  root = find_tag(metadata, 0xBF25)
  if root is None:
    raise RuntimeError("Invalid profileMetadata: missing 0xBF25 tag")

  result = {
    "iccid": None,
    "serviceProviderName": None,
    "profileName": None,
    "iconType": None,
    "icon": None,
    "profileClass": None,
  }

  # Iterate through TLV items
  for tag, value in iter_tlv(root):
    if tag == 0x5A:
      # ICCID in GSM BCD format
      result["iccid"] = tbcd_to_string(value)
    elif tag == 0x91:
      # Service provider name
      result["serviceProviderName"] = value.decode("utf-8", errors="ignore") or None
    elif tag == 0x92:
      # Profile name
      result["profileName"] = value.decode("utf-8", errors="ignore") or None
    elif tag == 0x93:
      # Icon type
      icon_type = int.from_bytes(value, "big")
      result["iconType"] = ICON_LABELS.get(icon_type, "unknown")
    elif tag == 0x94:
      # Icon (base64 encode)
      result["icon"] = base64.b64encode(value).decode("ascii")
    elif tag == 0x95:
      # Profile class
      pclass = int.from_bytes(value, "big")
      result["profileClass"] = CLASS_LABELS.get(pclass, "unknown")
    elif tag in (0xB6, 0xB7, 0x99):
      # Unhandled tags, skip
      pass

  return result


def download_profile(client: AtClient, activation_code: str) -> None:
  """Download eSIM profile using LPA activation code."""
  version, smdp_address, activation_code = parse_lpa_activation_code(activation_code)

  # Get eUICC challenge and info
  challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)
  b64_challenge = base64.b64encode(challenge).decode("ascii")
  b64_euicc_info = base64.b64encode(euicc_info).decode("ascii")

  auth_result = es9p_initiate_authentication_r(smdp_address, b64_challenge, b64_euicc_info)
  b64_authenticate_server_response = es10b_authenticate_server_r(
    client,
    auth_result["serverSigned1"],
    auth_result["serverSignature1"],
    auth_result["euiccCiPKIdToBeUsed"],
    auth_result["serverCertificate"],
  )
  client_result = es9p_authenticate_client_r(smdp_address, auth_result["transactionId"], b64_authenticate_server_response)

  metadata = es8p_metadata_parse(client_result["profileMetadata"])
  print(f'Downloading profile: {metadata["iccid"]} - {metadata["serviceProviderName"]} - {metadata["profileName"]}')

  # Prepare download on eUICC
  b64_prepare_download_response = es10b_prepare_download_r(
    client,
    client_result["smdpSigned2"],
    client_result["smdpSignature2"],
    client_result["smdpCertificate"],
  )

  # Get bound profile package from SM-DP+
  b64_bound_profile_package = es9p_get_bound_profile_package_r(
    smdp_address,
    auth_result["transactionId"],
    b64_prepare_download_response,
  )

  # Load bound profile package onto eUICC
  install_result = es10b_load_bound_profile_package_r(client, b64_bound_profile_package)
  if install_result["success"]:
    print(f"Profile installed successfully (seqNumber: {install_result['seqNumber']})")
  else:
    raise RuntimeError(f"Profile installation failed: {install_result}")


def build_cli() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Minimal AT-only lpac profile list and enable clone")
  parser.add_argument("--device", default=DEFAULT_DEVICE, help=f"Serial device path (default: {DEFAULT_DEVICE})")
  parser.add_argument("--baud", type=int, default=DEFAULT_BAUD, help=f"Serial baud rate (default: {DEFAULT_BAUD})")
  parser.add_argument(
    "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Serial read timeout in seconds (default: {DEFAULT_TIMEOUT})"
  )
  parser.add_argument("--verbose", action="store_true", help="Print raw AT traffic to stderr")
  parser.add_argument("--enable", type=str, help="Enable profile by ICCID")
  parser.add_argument("--disable", type=str, help="Disable profile by ICCID")
  parser.add_argument("--set-nickname", nargs=2, metavar=("ICCID", "NICKNAME"), help="Set profile nickname by ICCID")
  parser.add_argument("--list-notifications", action="store_true", help="Retrieve and display notifications from eUICC")
  parser.add_argument("--process-notifications", action="store_true", help="Process all notifications: send to SM-DP+ and remove from eUICC")
  parser.add_argument("--download", type=str, metavar="CODE", help="Download profile (LPA:1$smdp.io$CODE)")
  return parser


def main() -> None:
  args = build_cli().parse_args()
  client = AtClient(args.device, args.baud, args.timeout, args.verbose)
  try:
    client.ensure_capabilities()
    client.open_isdr()
    if args.enable:
      enable_profile(client, args.enable)
      # List profiles after enabling to show updated state
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
    elif args.disable:
      disable_profile(client, args.disable)
      # List profiles after disabling to show updated state
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
    elif args.set_nickname:
      iccid, nickname = args.set_nickname
      set_profile_nickname(client, iccid, nickname)
      # List profiles after setting nickname to show updated state
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
    elif args.list_notifications:
      notifications = list_notifications(client)
      print(json.dumps(notifications, indent=2))
    elif args.process_notifications:
      process_notifications(client)
    elif args.download:
      download_profile(client, args.download)
      # List profiles after downloading to show updated state
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
    else:
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
  finally:
    client.close()


if __name__ == "__main__":
  main()
