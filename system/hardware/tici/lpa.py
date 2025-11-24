#!/usr/bin/env python3

import argparse
import base64
import binascii
import json
import sys
from collections.abc import Generator
from typing import Optional

import requests
import serial
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerSequence


DEFAULT_DEVICE = "/dev/ttyUSB3"
DEFAULT_BAUD = 9600
DEFAULT_TIMEOUT = 5.0
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ES10X_MSS = 120

STATE_LABELS = {0: "disabled", 1: "enabled", 255: "unknown"}
ICON_LABELS = {0: "jpeg", 1: "png", 255: "unknown"}
CLASS_LABELS = {0: "test", 1: "provisioning", 2: "operational", 255: "unknown"}

# BPP Command IDs (from SGP.22)
ES10B_BPP_COMMAND_ID_INITIALISE_SECURE_CHANNEL = 0x01
ES10B_BPP_COMMAND_ID_CONFIGURE_ISDP = 0x02
ES10B_BPP_COMMAND_ID_STORE_METADATA = 0x03
ES10B_BPP_COMMAND_ID_STORE_METADATA2 = 0x04
ES10B_BPP_COMMAND_ID_REPLACE_SESSION_KEYS = 0x05
ES10B_BPP_COMMAND_ID_LOAD_PROFILE_ELEMENTS = 0x06
ES10B_BPP_COMMAND_ID_UNDEFINED = 0xFF

# Error Reasons (from SGP.22)
ES10B_ERROR_REASON_INCORRECT_INPUT_VALUES = 0x01
ES10B_ERROR_REASON_INVALID_SIGNATURE = 0x02
ES10B_ERROR_REASON_INVALID_TRANSACTION_ID = 0x03
ES10B_ERROR_REASON_UNSUPPORTED_CRT_VALUES = 0x04
ES10B_ERROR_REASON_UNSUPPORTED_REMOTE_OPERATION_TYPE = 0x05
ES10B_ERROR_REASON_UNSUPPORTED_PROFILE_CLASS = 0x06
ES10B_ERROR_REASON_SCP03T_STRUCTURE_ERROR = 0x07
ES10B_ERROR_REASON_SCP03T_SECURITY_ERROR = 0x08
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC = 0x09
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INSUFFICIENT_MEMORY_FOR_PROFILE = 0x0A
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INTERRUPTION = 0x0B
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_PE_PROCESSING_ERROR = 0x0C
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_MISMATCH = 0x0D
ES10B_ERROR_REASON_TEST_PROFILE_INSTALL_FAILED_DUE_TO_INVALID_NAA_KEY = 0x0E
ES10B_ERROR_REASON_PPR_NOT_ALLOWED = 0x0F
ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR = 0x10
ES10B_ERROR_REASON_UNDEFINED = 0xFF


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


def build_tlv(tag: int, value: bytes) -> bytes:
  """Build a TLV structure with proper length encoding."""
  if tag > 0xFF:
    # Multi-byte tag encoding (for tags like BF30, BF37)
    # High byte first, then low byte
    tag_bytes = bytearray([(tag >> 8) & 0xFF, tag & 0xFF])
  else:
    tag_bytes = bytearray([tag])

  length = len(value)
  if length <= 127:
    length_bytes = bytes([length])
  else:
    # Multi-byte length encoding
    length_bytes_len = (length.bit_length() + 7) // 8
    length_bytes = bytes([0x80 | length_bytes_len]) + length.to_bytes(length_bytes_len, "big")

  return bytes(tag_bytes) + length_bytes + value


def build_integer_tlv(tag: int, value: int) -> bytes:
  """Build a TLV structure containing an integer value."""
  if value == 0:
    value_bytes = bytes([0])
  else:
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
  return build_tlv(tag, value_bytes)


def build_string_tlv(tag: int, value: str) -> bytes:
  """Build a TLV structure containing a UTF-8 string."""
  return build_tlv(tag, value.encode("utf-8"))


def extract_integer(data: bytes) -> int:
  """Extract an integer value from TLV data."""
  if len(data) == 0:
    return 0
  return int.from_bytes(data, "big")


def extract_string(data: bytes) -> str:
  """Extract a UTF-8 string from TLV data."""
  return data.decode("utf-8", errors="ignore")


def parse_certificate(cert_der: bytes) -> RSA.RsaKey:
  """Parse X.509 certificate from DER format and extract public key."""
  try:
    # Convert DER to PEM format
    cert_pem = base64.b64encode(cert_der).decode("ascii")
    # Split into 64-character lines
    cert_pem_lines = [cert_pem[i : i + 64] for i in range(0, len(cert_pem), 64)]
    cert_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(cert_pem_lines) + "\n-----END CERTIFICATE-----"
    # Parse certificate - pycryptodome can parse PEM directly
    # The certificate contains the public key, so we extract it
    # For X.509 certificates, we need to parse the ASN.1 structure
    # Simplified approach: try to extract RSA public key from certificate
    # Parse certificate as DER sequence
    cert_seq = DerSequence()
    cert_seq.decode(cert_der)
    # Certificate structure: [tbsCertificate, signatureAlgorithm, signature]
    # tbsCertificate contains subjectPublicKeyInfo
    tbs_cert = cert_seq[0]
    # Parse tbsCertificate to find subjectPublicKeyInfo
    tbs_seq = DerSequence()
    tbs_seq.decode(tbs_cert)
    # subjectPublicKeyInfo is typically at index 6 in tbsCertificate
    if len(tbs_seq) > 6:
      spki = tbs_seq[6]
      # Parse subjectPublicKeyInfo: [algorithm, subjectPublicKey]
      spki_seq = DerSequence()
      spki_seq.decode(spki)
      # subjectPublicKey is the bit string containing the key
      if len(spki_seq) >= 2:
        public_key_bitstring = spki_seq[1]
        # Extract the key bytes (skip the unused bits byte if present)
        if isinstance(public_key_bitstring, bytes):
          key_bytes = public_key_bitstring
          # Remove the first byte if it's the unused bits indicator (usually 0x00)
          if len(key_bytes) > 0 and key_bytes[0] == 0:
            key_bytes = key_bytes[1:]
          # Parse RSA public key from the bitstring
          key_seq = DerSequence()
          key_seq.decode(key_bytes)
          # RSA public key: [modulus, exponent]
          if len(key_seq) >= 2:
            modulus = key_seq[0]
            exponent = key_seq[1]
            # Create RSA key object
            return RSA.construct((modulus, exponent))
    raise RuntimeError("Could not extract public key from certificate")
  except Exception as e:
    raise RuntimeError(f"Failed to parse certificate: {e}") from e


def verify_rsa_signature(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
  """Verify RSA signature using SHA256 hash."""
  try:
    hash_obj = SHA256.new(data)
    verifier = pkcs1_15.new(public_key)
    verifier.verify(hash_obj, signature)
    return True
  except (ValueError, TypeError):
    return False


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


# ES10b Commands (eUICC Communication)

def es10b_get_euicc_challenge_r(client: AtClient) -> str:
  """Get eUICC challenge (ES10b GetEUICCChallenge).

  Returns base64-encoded challenge response.
  """
  # Build request: BF26 (GetEUICCChallenge) with empty content
  request = bytes([0xBF, 0x26, 0x00])
  response = es10x_command(client, request)
  # Response is BF26 containing the challenge data
  challenge_data = find_tag(response, 0xBF26)
  if challenge_data is None:
    raise RuntimeError("Missing GetEUICCChallengeResponse (0xBF26)")
  # The challenge data is returned as-is, encode to base64 for HTTP transmission
  return base64.b64encode(challenge_data).decode("ascii")


def es10b_get_euicc_info_r(client: AtClient) -> str:
  """Get eUICC info (ES10b GetEUICCInfo).

  Returns base64-encoded eUICC info response.
  """
  # Build request: BF27 (GetEUICCInfo) with empty content
  request = bytes([0xBF, 0x27, 0x00])
  response = es10x_command(client, request)
  # Response is BF27 containing eUICC info
  info_data = find_tag(response, 0xBF27)
  if info_data is None:
    raise RuntimeError("Missing GetEUICCInfoResponse (0xBF27)")
  # The info data is returned as-is, encode to base64 for HTTP transmission
  return base64.b64encode(info_data).decode("ascii")


def es10b_get_euicc_challenge_and_info(client: AtClient) -> tuple[str, str]:
  """Get both eUICC challenge and info.

  Returns tuple of (challenge, info) both base64-encoded.
  """
  challenge = es10b_get_euicc_challenge_r(client)
  info = es10b_get_euicc_info_r(client)
  return challenge, info


def es10b_authenticate_server_r(
  client: AtClient,
  server_signed1_b64: str,
  server_signature1_b64: str,
  euicc_ci_pk_id_to_be_used_b64: str,
  server_certificate_b64: str,
  matching_id: Optional[str] = None,
  imei: Optional[str] = None,
) -> tuple[bytes, str]:
  """Authenticate server (ES10b AuthenticateServer).

  Verifies server signature and returns transaction ID and base64-encoded response.
  """
  # Decode base64 inputs
  server_signed1 = base64.b64decode(server_signed1_b64)
  server_signature1 = base64.b64decode(server_signature1_b64)
  euicc_ci_pk_id = base64.b64decode(euicc_ci_pk_id_to_be_used_b64)
  server_certificate = base64.b64decode(server_certificate_b64)

  # Verify server signature
  public_key = parse_certificate(server_certificate)
  if not verify_rsa_signature(server_signed1, server_signature1, public_key):
    raise RuntimeError("Server signature verification failed")

  # Extract transaction ID from serverSigned1
  # serverSigned1 is a SEQUENCE containing transactionId (tag 0x80)
  transaction_id_data = find_tag(server_signed1, 0x80)
  if transaction_id_data is None:
    raise RuntimeError("Missing transaction ID in serverSigned1")
  transaction_id = transaction_id_data

  # Build AuthenticateServerRequest
  # BF30 [length] A0 [length] [serverSigned1] [serverSignature1] [euiccCiPKIdToBeUsed] [serverCertificate]
  request_content = bytearray()
  request_content.extend(build_tlv(0x30, server_signed1))  # serverSigned1 as SEQUENCE
  request_content.extend(build_tlv(0x5F37, server_signature1))  # serverSignature1
  request_content.extend(build_tlv(0x04, euicc_ci_pk_id))  # euiccCiPKIdToBeUsed (OCTET STRING)
  request_content.extend(build_tlv(0x70, server_certificate))  # serverCertificate

  # Add optional matching ID and IMEI
  if matching_id:
    matching_id_bytes = matching_id.encode("utf-8")
    request_content.extend(build_tlv(0x81, matching_id_bytes))
  if imei:
    imei_tbcd = string_to_tbcd(imei)
    request_content.extend(build_tlv(0x82, imei_tbcd))

  a0_content = bytes(request_content)
  bf30_content = build_tlv(0xA0, a0_content)
  request = build_tlv(0xBF30, bf30_content)

  # Send command
  response = es10x_command(client, request)

  # Parse response: BF30 containing AuthenticateServerResponse
  response_data = find_tag(response, 0xBF30)
  if response_data is None:
    raise RuntimeError("Missing AuthenticateServerResponse (0xBF30)")

  # Response contains transaction ID and other data
  response_b64 = base64.b64encode(response_data).decode("ascii")
  return transaction_id, response_b64


def es10b_prepare_download_r(
  client: AtClient,
  smdp_signed2_b64: str,
  smdp_signature2_b64: str,
  smdp_certificate_b64: str,
  confirmation_code: Optional[str] = None,
) -> str:
  """Prepare download (ES10b PrepareDownload).

  Verifies SM-DP+ signature and returns base64-encoded PrepareDownloadResponse.
  """
  # Decode base64 inputs
  smdp_signed2 = base64.b64decode(smdp_signed2_b64)
  smdp_signature2 = base64.b64decode(smdp_signature2_b64)
  smdp_certificate = base64.b64decode(smdp_certificate_b64)

  # Verify SM-DP+ signature
  public_key = parse_certificate(smdp_certificate)
  if not verify_rsa_signature(smdp_signed2, smdp_signature2, public_key):
    raise RuntimeError("SM-DP+ signature verification failed")

  # Build PrepareDownloadRequest
  # BF37 [length] A0 [length] [smdpSigned2] [smdpSignature2] [smdpCertificate] [optional hashCC]
  request_content = bytearray()
  request_content.extend(build_tlv(0x30, smdp_signed2))  # smdpSigned2 as SEQUENCE
  request_content.extend(build_tlv(0x5F37, smdp_signature2))  # smdpSignature2
  request_content.extend(build_tlv(0x70, smdp_certificate))  # smdpCertificate

  # Add confirmation code hash if provided
  if confirmation_code:
    # Hash confirmation code with SHA256
    hash_obj = SHA256.new(confirmation_code.encode("utf-8"))
    hash_cc = hash_obj.digest()
    request_content.extend(build_tlv(0x81, hash_cc))  # hashCC

  a0_content = bytes(request_content)
  bf37_content = build_tlv(0xA0, a0_content)
  request = build_tlv(0xBF37, bf37_content)

  # Send command
  response = es10x_command(client, request)

  # Parse response: BF37 containing PrepareDownloadResponse
  response_data = find_tag(response, 0xBF37)
  if response_data is None:
    raise RuntimeError("Missing PrepareDownloadResponse (0xBF37)")

  return base64.b64encode(response_data).decode("ascii")


def es10b_load_bound_profile_package_r(client: AtClient, bound_profile_package_b64: str) -> dict:
  """Load bound profile package (ES10b LoadBoundProfilePackage).

  Returns result dictionary with bppCommandId and errorReason.
  """
  # Decode base64 bound profile package
  bpp = base64.b64decode(bound_profile_package_b64)

  result = {
    "bppCommandId": ES10B_BPP_COMMAND_ID_UNDEFINED,
    "errorReason": ES10B_ERROR_REASON_UNDEFINED,
  }

  # Build LoadBoundProfilePackage request
  # BF38 [length] A0 [length] [boundProfilePackage]
  a0_content = build_tlv(0xA0, bpp)
  request = build_tlv(0xBF38, a0_content)

  # Send the entire bound profile package to eUICC
  try:
    response = es10x_command(client, request)
  except RuntimeError as e:
    error_msg = str(e)
    result["errorReason"] = ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR
    raise RuntimeError(f"Profile installation failed: {error_msg}") from e

  # Parse ProfileInstallationResult from response
  # Response structure: BF37 [length] A0 [length] [ProfileInstallationResultData]
  result_data = find_tag(response, 0xBF37)
  if result_data:
    # Parse ProfileInstallationResultData
    result_content = find_tag(result_data, 0xA0)
    if result_content:
      # Check for finalResult (A2 tag)
      final_result = find_tag(result_content, 0xA2)
      if final_result:
        # Parse finalResult - A0 = SuccessResult, A1 = ErrorResult
        success = find_tag(final_result, 0xA0)
        if success is not None:
          # Success
          result["bppCommandId"] = 0
          result["errorReason"] = 0
          return result

        error_result = find_tag(final_result, 0xA1)
        if error_result is not None:
          # Parse error details
          bpp_command_id = find_tag(error_result, 0x80)
          error_reason = find_tag(error_result, 0x81)
          if bpp_command_id:
            result["bppCommandId"] = extract_integer(bpp_command_id)
          if error_reason:
            result["errorReason"] = extract_integer(error_reason)
          raise RuntimeError(
            f"Profile installation failed: commandId=0x{result['bppCommandId']:02X}, errorReason=0x{result['errorReason']:02X}"
          )

  # If we get here, assume success
  result["bppCommandId"] = 0
  result["errorReason"] = 0
  return result


# ES9p Commands (HTTP to SM-DP+)

def es9p_initiate_authentication(smdp_url: str, euicc_challenge: str, euicc_info: str) -> dict:
  """Initiate authentication with SM-DP+ server (ES9p InitiateAuthentication).

  Returns dictionary with serverSigned1, serverSignature1, euiccCiPKIdToBeUsed, serverCertificate.
  """
  url = f"{smdp_url}/gsma/rsp2/es9p/initiateAuthentication"
  payload = {
    "euiccChallenge": euicc_challenge,
    "euiccInfo1": euicc_info,
  }

  response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=30)
  response.raise_for_status()

  data = response.json()
  return {
    "serverSigned1": data["serverSigned1"],
    "serverSignature1": data["serverSignature1"],
    "euiccCiPKIdToBeUsed": data["euiccCiPKIdToBeUsed"],
    "serverCertificate": data["serverCertificate"],
  }


def es9p_authenticate_client(smdp_url: str, authenticate_server_response: str) -> dict:
  """Authenticate client with SM-DP+ server (ES9p AuthenticateClient).

  Returns dictionary with transactionId, profileMetadata, smdpSigned2, smdpSignature2, smdpCertificate.
  """
  url = f"{smdp_url}/gsma/rsp2/es9p/authenticateClient"
  payload = {
    "authenticateServerResponse": authenticate_server_response,
  }

  response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=30)
  response.raise_for_status()

  data = response.json()
  return {
    "transactionId": data.get("transactionId"),
    "profileMetadata": data.get("profileMetadata"),
    "smdpSigned2": data["smdpSigned2"],
    "smdpSignature2": data["smdpSignature2"],
    "smdpCertificate": data["smdpCertificate"],
  }


def es9p_get_bound_profile_package(smdp_url: str, prepare_download_response: str) -> str:
  """Get bound profile package from SM-DP+ server (ES9p GetBoundProfilePackage).

  Returns base64-encoded bound profile package.
  """
  url = f"{smdp_url}/gsma/rsp2/es9p/getBoundProfilePackage"
  payload = {
    "prepareDownloadResponse": prepare_download_response,
  }

  response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=300)
  response.raise_for_status()

  data = response.json()
  return data["boundProfilePackage"]


# Activation Code Parsing

def parse_activation_code(activation_code: str) -> dict:
  """Parse LPA activation code string.

  Format: LPA:1$<smdp-address>$<activation-token>
  Examples:
    - LPA:1$smdp.io$K2-2MVZMV-ZTV9GW
    - LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5

  Returns dictionary with smdp_url and activation_token.
  """
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format: must start with 'LPA:'")

  parts = activation_code.split("$")
  if len(parts) < 3:
    raise ValueError("Invalid activation code format: expected at least 3 parts separated by '$'")

  version = parts[0]  # LPA:1
  if not version.startswith("LPA:1"):
    raise ValueError(f"Unsupported activation code version: {version}")

  smdp_address = parts[1]
  activation_token = parts[2] if len(parts) > 2 else None

  # Convert SM-DP+ address to full URL
  if not smdp_address.startswith(("http://", "https://")):
    smdp_url = f"https://{smdp_address}"
  else:
    smdp_url = smdp_address

  return {
    "smdp_url": smdp_url,
    "activation_token": activation_token,
  }


# Main Download Function

def download_profile(client: AtClient, activation_code: str) -> None:
  """Download and install a profile using LPA activation code.

  Orchestrates the complete SGP.22 profile download flow.
  """
  # Parse activation code
  parsed = parse_activation_code(activation_code)
  smdp_url = parsed["smdp_url"]
  activation_token = parsed.get("activation_token")

  # Step 1: Get eUICC challenge and info
  euicc_challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)

  # Step 2: Initiate authentication with SM-DP+
  auth_data = es9p_initiate_authentication(smdp_url, euicc_challenge, euicc_info)

  # Step 3: Authenticate server
  transaction_id, authenticate_server_response = es10b_authenticate_server_r(
    client,
    auth_data["serverSigned1"],
    auth_data["serverSignature1"],
    auth_data["euiccCiPKIdToBeUsed"],
    auth_data["serverCertificate"],
  )

  # Step 4: Authenticate client
  client_data = es9p_authenticate_client(smdp_url, authenticate_server_response)

  # Step 5: Prepare download (with optional confirmation code)
  prepare_download_response = es10b_prepare_download_r(
    client,
    client_data["smdpSigned2"],
    client_data["smdpSignature2"],
    client_data["smdpCertificate"],
    activation_token,  # Use activation token as confirmation code if provided
  )

  # Step 6: Get bound profile package
  bound_profile_package = es9p_get_bound_profile_package(smdp_url, prepare_download_response)

  # Step 7: Load bound profile package
  result = es10b_load_bound_profile_package_r(client, bound_profile_package)

  # Check result
  if result["errorReason"] != 0:
    error_msg = f"Profile installation failed: commandId=0x{result['bppCommandId']:02X}, errorReason=0x{result['errorReason']:02X}"
    raise RuntimeError(error_msg)

  print("Profile downloaded and installed successfully")


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
  parser.add_argument("--download", type=str, help="Download profile using LPA activation code (e.g., LPA:1$smdp.io$TOKEN)")
  return parser


def main() -> None:
  args = build_cli().parse_args()
  client = AtClient(args.device, args.baud, args.timeout, args.verbose)
  try:
    client.ensure_capabilities()
    client.open_isdr()
    if args.download:
      download_profile(client, args.download)
      # List profiles after downloading to show updated state
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
    elif args.enable:
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
    else:
      profiles = request_profile_info(client)
      print(json.dumps(profiles, indent=2))
  finally:
    client.close()


if __name__ == "__main__":
  main()
