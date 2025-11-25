#!/usr/bin/env python3

import argparse
import base64
import binascii
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
  """Encode TLV with proper DER length encoding."""
  value_len = len(value)
  if value_len <= 127:
    return bytes([tag, value_len]) + value
  else:
    length_bytes = value_len.to_bytes((value_len.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + value


def build_authenticate_server_request(
  server_signed1: bytes, server_signature1: bytes, euicc_ci_pk_id: bytes, server_certificate: bytes,
  matching_id: Optional[str] = None, imei: Optional[str] = None
) -> bytes:
  """Build DER-encoded AuthenticateServer request (tag 0xBF38)."""
  # Structure: BF38 [length] 30 [serverSigned1] 5F37 [serverSignature1] 04 [euiccCiPKId] 30 [serverCertificate] A0 [CtxParams1]
  # CtxParams1 (A0) contains: optional 80 [matchingId] A1 [deviceInfo]
  # deviceInfo (A1) contains: 80 [tac] A1 [deviceCapabilities]
  # deviceCapabilities (A1) contains: optional 82 [imei]

  # Build deviceCapabilities (A1): optional 82 [imei]
  device_capabilities = bytearray()
  if imei:
    imei_bytes = hex_to_gsmbcd(imei)
    device_capabilities.extend([0x82, len(imei_bytes)])
    device_capabilities.extend(imei_bytes)

  # Build deviceInfo (A1): 80 [tac] A1 [deviceCapabilities]
  # Reference shows deviceCapabilities (A1) is always present, even if empty
  tac = bytes([0x35, 0x29, 0x06, 0x11])  # Default TAC
  device_info = bytearray([0x80, len(tac)]) + tac
  # deviceCapabilities (A1) is always present
  if device_capabilities:
    device_info.extend([0xA1, len(device_capabilities)])
    device_info.extend(device_capabilities)
  else:
    # Empty deviceCapabilities (A1) - just tag and length 0
    device_info.extend([0xA1, 0x00])

  # Build CtxParams1 (A0): optional 80 [matchingId] A1 [deviceInfo]
  ctx_params = bytearray()
  if matching_id:
    matching_id_bytes = matching_id.encode("utf-8")
    ctx_params.extend([0x80, len(matching_id_bytes)])
    ctx_params.extend(matching_id_bytes)
  ctx_params.extend([0xA1, len(device_info)])
  ctx_params.extend(device_info)

  # Build main request: 30 [serverSigned1] 5F37 [serverSignature1] 04 [euiccCiPKId] 30 [serverCertificate] A0 [CtxParams1]
  # The decoded bytes are already DER-encoded structures with their tags
  request_content = bytearray()
  # Check if structures already have their tags, or if we need to add them
  # serverSigned1 should start with 0x30
  if not server_signed1.startswith(bytes([0x30])):
    request_content.extend(encode_tlv(0x30, server_signed1))
  else:
    request_content.extend(server_signed1)
  # serverSignature1 should start with 0x5F37
  if not server_signature1.startswith(bytes([0x5F, 0x37])):
    sig_len = len(server_signature1)
    if sig_len <= 127:
      request_content.extend([0x5F, 0x37, sig_len])
    else:
      length_bytes = sig_len.to_bytes((sig_len.bit_length() + 7) // 8, "big")
      request_content.extend([0x5F, 0x37, 0x80 | len(length_bytes)])
      request_content.extend(length_bytes)
    request_content.extend(server_signature1)
  else:
    request_content.extend(server_signature1)
  # euiccCiPKId should start with 0x04
  if not euicc_ci_pk_id.startswith(bytes([0x04])):
    request_content.extend(encode_tlv(0x04, euicc_ci_pk_id))
  else:
    request_content.extend(euicc_ci_pk_id)
  # serverCertificate should start with 0x30
  if not server_certificate.startswith(bytes([0x30])):
    request_content.extend(encode_tlv(0x30, server_certificate))
  else:
    request_content.extend(server_certificate)
  # CtxParams1 needs to be encoded
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

  # Build and send request
  request = build_authenticate_server_request(server_signed1, server_signature1, euicc_ci_pk_id, server_certificate, matching_id, imei)
  print(f"AuthenticateServerRequest length: {len(request)} bytes", file=sys.stderr)
  print(f"Request starts with: {request[:10].hex()}", file=sys.stderr)
  response = es10x_command(client, request)
  print(f"Raw response length: {len(response)} bytes", file=sys.stderr)
  print(f"Raw response hex: {response.hex()}", file=sys.stderr)

  # Return transaction_id and base64 encoded response
  # Response should be AuthenticateServerResponse (tag 0xBF38)
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError(f"Invalid AuthenticateServerResponse: expected tag 0xBF38, got {response[:4].hex() if len(response) >= 4 else 'too short'}")

  # Check if response seems too short (might be an error response)
  if len(response) < 50:
    print(f"ERROR: AuthenticateServerResponse is very short ({len(response)} bytes): {response.hex()}", file=sys.stderr)
    # Parse the response to see what error it contains
    root = find_tag(response, 0xBF38)
    if root:
      print(f"Response content: {root.hex()}", file=sys.stderr)
      # The response structure: A1 [content] where content has 80 00 [empty transactionId] and 02 01 7F [error code]
      # Check for error code tag 0x02
      for tag, value in iter_tlv(root):
        if tag == 0x02 and len(value) > 0:
          error_code = value[0]
          raise RuntimeError(f"eUICC returned error code 0x{error_code:02X} in AuthenticateServerResponse - request rejected")
        elif tag == 0x80 and len(value) == 0:
          print("WARNING: Empty transactionId in response", file=sys.stderr)
    raise RuntimeError(f"AuthenticateServerResponse too short ({len(response)} bytes) - eUICC rejected the request. Response: {response.hex()}")

  b64_response = base64.b64encode(response).decode("ascii")
  print(f"AuthenticateServerResponse length: {len(response)} bytes", file=sys.stderr)
  return transaction_id, b64_response


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


def build_list_notifications_request(profile_management_operation: Optional[int] = None) -> bytes:
  """Build DER-encoded ListNotifications request.

  Structure: BF28 [length] A0 [length] [optional profileManagementOperation]
  BF28 = ListNotifications tag
  A0 = Context tag for ListNotificationRequest
  According to SGP.22 specification section 5.7.9, ListNotifications retrieves notifications stored on the eUICC.
  If profileManagementOperation is omitted, all notifications are returned.
  """
  # Build TLV structure: BF28 [length] A0 [length] [optional profileManagementOperation]
  # A0 is the context tag for ListNotificationRequest
  a0_content = bytearray()
  if profile_management_operation is not None:
    # Add profileManagementOperation field (tag 0x83, integer)
    # Encode as integer (typically 1-4 bytes)
    op_bytes = profile_management_operation.to_bytes((profile_management_operation.bit_length() + 7) // 8 or 1, "big")
    a0_content.extend([0x83, len(op_bytes)])
    a0_content.extend(op_bytes)

  bf28_content = bytearray([0xA0, len(a0_content)]) + a0_content
  bf28_length = len(bf28_content)
  # Handle length encoding: if length > 127, use multi-byte encoding
  if bf28_length <= 127:
    return bytes([0xBF, 0x28, bf28_length]) + bf28_content
  else:
    # Multi-byte length encoding
    length_bytes = bf28_length.to_bytes((bf28_length.bit_length() + 7) // 8, "big")
    return bytes([0xBF, 0x28, 0x80 | len(length_bytes)]) + length_bytes + bf28_content


def decode_notification_metadata_list(data: bytes) -> list[dict]:
  """Parse NotificationMetadataList TLV structure from ListNotificationResponse.

  Response structure: BF28 [length] A0 [length] [NotificationMetadataList or listNotificationsResultError]
  NotificationMetadataList is a SEQUENCE OF NotificationMetadata.
  According to SGP.22 and lpac reference implementation.
  """
  root = find_tag(data, 0xBF28)
  if root is None:
    raise RuntimeError("Missing ListNotificationResponse (0xBF28)")

  # Check for error first (tag 0x80) - listNotificationsResultError
  error_data = find_tag(root, 0x80)
  if error_data is not None:
    error_code = error_data[0] if len(error_data) > 0 else 0
    raise RuntimeError(f"ListNotifications failed with error code: 0x{error_code:02X}")

  # Find NotificationMetadataList (tag A0)
  # NotificationMetadataList is a SEQUENCE OF NotificationMetadata
  metadata_list_data = find_tag(root, 0xA0)
  if metadata_list_data is None:
    # No notifications available
    return []

  notifications: list[dict] = []
  for _, value in iter_tlv(metadata_list_data):
    notification = decode_notification_metadata(value)
    if notification:
      notifications.append(notification)

  return notifications


def decode_notification_metadata(metadata_data: bytes) -> Optional[dict]:
  """Parse individual NotificationMetadata TLV structure.

  Extracts sequence number, profile management operation, notification address, and ICCID.
  NotificationMetadata structure contains:
  - 0x82: seqNumber (integer) - required
  - 0x83: profileManagementOperation (bitmask) - required
  - 0x84: notificationAddress (UTF8String) - required
  - 0x5A: ICCID (TBCD) - optional
  """
  notification: dict = {
    "seqNumber": None,
    "profileManagementOperation": None,
    "notificationAddress": None,
    "iccid": None,
  }

  for tag, value in iter_tlv(metadata_data):
    if tag == 0x82:  # seqNumber
      if len(value) > 0:
        notification["seqNumber"] = int.from_bytes(value, "big")
    elif tag == 0x83:  # profileManagementOperation
      if len(value) > 0:
        notification["profileManagementOperation"] = int.from_bytes(value, "big")
    elif tag == 0x84:  # notificationAddress (UTF8String)
      notification["notificationAddress"] = value.decode("utf-8", errors="ignore")
    elif tag == 0x5A:  # ICCID (optional)
      notification["iccid"] = tbcd_to_string(value)

  # Only return notification if it has required fields
  if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"] is not None:
    return notification
  return None


def list_notifications(client: AtClient, profile_management_operation: Optional[int] = None) -> list[dict]:
  """Retrieve notifications stored on the eUICC via ListNotifications command.

  Sends the ES10x ListNotifications command and parses the response.
  Returns a list of notification metadata dictionaries.
  According to SGP.22 specification section 5.7.9.
  """
  der_request = build_list_notifications_request(profile_management_operation)
  payload = es10x_command(client, der_request)

  # Parse and return the notification metadata list
  return decode_notification_metadata_list(payload)


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


def download_profile(client: AtClient, activation_code: str) -> None:
  """Download eSIM profile using LPA activation code."""
  version, smdp_address, activation_code = parse_lpa_activation_code(activation_code)
  print(f"Downloading profile from {smdp_address} with activation code {activation_code}, version {version}", file=sys.stderr)

  # Get eUICC challenge and info
  challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)
  b64_challenge = base64.b64encode(challenge).decode("ascii")
  b64_euicc_info = base64.b64encode(euicc_info).decode("ascii")

  # Initiate authentication with SM-DP+
  auth_result = es9p_initiate_authentication_r(smdp_address, b64_challenge, b64_euicc_info)
  print(f"Transaction ID: {auth_result['transactionId']}", file=sys.stderr)

  # Authenticate server on eUICC
  transaction_id_bytes, b64_authenticate_server_response = es10b_authenticate_server_r(
    client,
    auth_result["serverSigned1"],
    auth_result["serverSignature1"],
    auth_result["euiccCiPKIdToBeUsed"],
    auth_result["serverCertificate"],
    matching_id=None,  # TODO: extract from activation_code if needed
    imei=None,  # TODO: get IMEI if needed
  )
  print(f"Server authenticated, eUICC transaction ID: {transaction_id_bytes.hex()}", file=sys.stderr)

  # Authenticate client with SM-DP+
  # Use the HTTP transaction ID from initiateAuthentication response (as string, not base64)
  http_transaction_id = auth_result["transactionId"]
  print(f"Using HTTP transaction ID: {http_transaction_id}", file=sys.stderr)
  print(f"AuthenticateServerResponse length: {len(b64_authenticate_server_response)} chars (base64)", file=sys.stderr)
  resp_data = base64.b64decode(b64_authenticate_server_response)
  print(f"AuthenticateServerResponse decoded length: {len(resp_data)} bytes", file=sys.stderr)
  if len(resp_data) < 20:
    print(f"WARNING: AuthenticateServerResponse seems too short: {resp_data.hex()}", file=sys.stderr)
  client_result = es9p_authenticate_client_r(smdp_address, http_transaction_id, b64_authenticate_server_response)
  print(f"Client authenticated, profile metadata: {len(client_result['profileMetadata'])} bytes", file=sys.stderr)


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
