#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import requests
import serial
import subprocess
import sys

from collections.abc import Generator


DEFAULT_DEVICE = "/dev/ttyUSB3"
DEFAULT_BAUD = 9600
DEFAULT_TIMEOUT = 5.0
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ES10X_MSS = 120

# TLV Tags
TAG_ICCID = 0x5A
TAG_STATUS = 0x80
TAG_EUICC_INFO = 0xBF20
TAG_PREPARE_DOWNLOAD = 0xBF21
TAG_PROFILE_INFO_LIST = 0xBF2D
TAG_EUICC_CHALLENGE = 0xBF2E
TAG_SET_NICKNAME = 0xBF29
TAG_LIST_NOTIFICATION = 0xBF28
TAG_RETRIEVE_NOTIFICATION = 0xBF2B
TAG_NOTIFICATION_METADATA = 0xBF2F
TAG_NOTIFICATION_SENT = 0xBF30
TAG_ENABLE_PROFILE = 0xBF31
TAG_DISABLE_PROFILE = 0xBF32
TAG_BPP = 0xBF36
TAG_PROFILE_INSTALL_RESULT = 0xBF37
TAG_AUTH_SERVER = 0xBF38

STATE_LABELS = {0: "disabled", 1: "enabled", 255: "unknown"}
ICON_LABELS = {0: "jpeg", 1: "png", 255: "unknown"}
CLASS_LABELS = {0: "test", 1: "provisioning", 2: "operational", 255: "unknown"}
PROFILE_ERROR_CODES = {
  0x01: "iccidOrAidNotFound", 0x02: "profileNotInDisabledState",
  0x03: "disallowedByPolicy", 0x04: "wrongProfileReenabling",
  0x05: "catBusy", 0x06: "undefinedError",
}


class AtClient:
  def __init__(self, device: str, baud: int, timeout: float, verbose: bool) -> None:
    self.ser = serial.Serial(device, baudrate=baud, timeout=timeout)
    self.verbose = verbose
    self.channel: str | None = None
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
    for line in self.query(f'AT+CCHO="{ISDR_AID}"'):
      if line.startswith("+CCHO:") and (ch := line.split(":", 1)[1].strip()):
        self.channel = ch
        return
    raise RuntimeError("Failed to open ISD-R application")

  def send_apdu(self, apdu: bytes) -> tuple[bytes, int, int]:
    if not self.channel:
      raise RuntimeError("Logical channel is not open")
    hex_payload = apdu.hex().upper()
    for line in self.query(f'AT+CGLA={self.channel},{len(hex_payload)},"{hex_payload}"'):
      if line.startswith("+CGLA:"):
        parts = line.split(":", 1)[1].split(",", 1)
        if len(parts) == 2:
          data = bytes.fromhex(parts[1].strip().strip('"'))
          if len(data) >= 2:
            return data[:-2], data[-2], data[-1]
    raise RuntimeError("Missing +CGLA response")


# --- TLV utilities ---

def iter_tlv(data: bytes, with_positions: bool = False) -> Generator:
  idx, length = 0, len(data)
  while idx < length:
    start_pos = idx
    tag = data[idx]; idx += 1
    if tag & 0x1F == 0x1F:  # Multi-byte tag
      tag_value = tag
      while idx < length:
        next_byte = data[idx]; idx += 1
        tag_value = (tag_value << 8) | next_byte
        if not (next_byte & 0x80):
          break
    else:
      tag_value = tag
    if idx >= length:
      break
    size = data[idx]; idx += 1
    if size & 0x80:  # Multi-byte length
      num_bytes = size & 0x7F
      if idx + num_bytes > length:
        break
      size = int.from_bytes(data[idx : idx + num_bytes], "big")
      idx += num_bytes
    if idx + size > length:
      break
    value = data[idx : idx + size]
    idx += size
    yield (tag_value, value, start_pos, idx) if with_positions else (tag_value, value)


def find_tag(data: bytes, target: int) -> bytes | None:
  return next((v for t, v in iter_tlv(data) if t == target), None)


def encode_tlv(tag: int, value: bytes) -> bytes:
  tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF]) if tag > 255 else bytes([tag])
  vlen = len(value)
  if vlen <= 127:
    return tag_bytes + bytes([vlen]) + value
  length_bytes = vlen.to_bytes((vlen.bit_length() + 7) // 8, "big")
  return tag_bytes + bytes([0x80 | len(length_bytes)]) + length_bytes + value


def tbcd_to_string(raw: bytes) -> str:
  return "".join(str(n) for b in raw for n in (b & 0x0F, b >> 4) if n <= 9)


def string_to_tbcd(s: str) -> bytes:
  digits = [int(c) for c in s if c.isdigit()]
  return bytes(digits[i] | ((digits[i + 1] if i + 1 < len(digits) else 0xF) << 4) for i in range(0, len(digits), 2))


def base64_trim(s: str) -> str:
  return "".join(c for c in s if c not in "\n\r \t")


# --- Shared helpers ---

def _int_bytes(n: int) -> bytes:
  """Encode a positive integer as minimal big-endian bytes (at least 1 byte)."""
  return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")


def _extract_status(response: bytes, tag: int, name: str) -> int:
  """Extract the status byte from a tagged ES10x response."""
  root = find_tag(response, tag)
  if root is None:
    raise RuntimeError(f"Missing {name}Response")
  status = find_tag(root, TAG_STATUS)
  if status is None:
    raise RuntimeError(f"Missing status in {name}Response")
  return status[0]


# Profile field decoders: TLV tag -> (field_name, decoder)
_PROFILE_FIELDS = {
  TAG_ICCID: ("iccid", lambda v: tbcd_to_string(v)),
  0x4F: ("isdpAid", lambda v: v.hex().upper()),
  0x9F70: ("profileState", lambda v: STATE_LABELS.get(int.from_bytes(v, "big"), "unknown")),
  0x90: ("profileNickname", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x91: ("serviceProviderName", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x92: ("profileName", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x93: ("iconType", lambda v: ICON_LABELS.get(int.from_bytes(v, "big"), "unknown")),
  0x94: ("icon", lambda v: base64.b64encode(v).decode("ascii")),
  0x95: ("profileClass", lambda v: CLASS_LABELS.get(int.from_bytes(v, "big"), "unknown")),
}


def _decode_profile_fields(data: bytes) -> dict:
  """Parse known profile metadata TLV fields into a dict."""
  result = {}
  for tag, value in iter_tlv(data):
    if (field := _PROFILE_FIELDS.get(tag)):
      result[field[0]] = field[1](value)
  return result


# --- ES10x command transport ---

def es10x_command(client: AtClient, data: bytes) -> bytes:
  response = bytearray()
  sequence = 0
  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + ES10X_MSS]
    offset += len(chunk)
    # STORE DATA: CLA=0x80, INS=0xE2, P1=0x91(last)/0x11(more), P2=sequence
    apdu = bytes([0x80, 0xE2, 0x91 if offset == len(data) else 0x11, sequence & 0xFF, len(chunk)]) + chunk
    segment, sw1, sw2 = client.send_apdu(apdu)
    response.extend(segment)
    while True:
      if sw1 == 0x61:  # More data available
        segment, sw1, sw2 = client.send_apdu(bytes([0x80, 0xC0, 0x00, 0x00, sw2 or 0]))
        response.extend(segment)
        continue
      if (sw1 & 0xF0) == 0x90:
        break
      raise RuntimeError(f"APDU failed with SW={sw1:02X}{sw2:02X}")
    sequence += 1
  return bytes(response)


# --- ES9P HTTP ---

def es9p_request(smdp_address: str, endpoint: str, payload: dict, error_prefix: str = "Request") -> dict:
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/{endpoint}"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  if not resp.content:
    return {}
  data = resp.json()
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      sd = status.get("statusCodeData", {})
      raise RuntimeError(f"{error_prefix} failed: {sd.get('reasonCode', 'unknown')}/{sd.get('subjectCode', 'unknown')} - {sd.get('message', 'unknown')}")
  return data


# --- Profile operations ---

def decode_profiles(blob: bytes) -> list[dict]:
  root = find_tag(blob, TAG_PROFILE_INFO_LIST)
  if root is None:
    raise RuntimeError("Missing ProfileInfoList")
  list_ok = find_tag(root, 0xA0)
  if list_ok is None:
    return []
  defaults = {name: None for name, _ in _PROFILE_FIELDS.values()}
  return [{**defaults, **_decode_profile_fields(value)} for tag, value in iter_tlv(list_ok) if tag == 0xE3]


def request_profile_info(client: AtClient) -> list[dict]:
  return decode_profiles(es10x_command(client, bytes.fromhex("BF2D00")))


def _toggle_profile(client: AtClient, tag: int, iccid: str, refresh: bool, action: str) -> None:
  inner = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
  if not refresh:
    inner += encode_tlv(0x81, b'\x00')
  code = _extract_status(es10x_command(client, encode_tlv(tag, encode_tlv(0xA0, inner))), tag, f"{action.capitalize()}Profile")
  if code == 0x00:
    return
  if code == 0x02:
    print(f"profile {iccid} already {action}d")
    return
  raise RuntimeError(f"{action.capitalize()}Profile failed: {PROFILE_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})")


def enable_profile(client: AtClient, iccid: str, refresh: bool = True) -> None:
  _toggle_profile(client, TAG_ENABLE_PROFILE, iccid, refresh, "enable")


def disable_profile(client: AtClient, iccid: str, refresh: bool = True) -> None:
  _toggle_profile(client, TAG_DISABLE_PROFILE, iccid, refresh, "disable")


def set_profile_nickname(client: AtClient, iccid: str, nickname: str) -> None:
  nickname_bytes = nickname.encode("utf-8")
  if len(nickname_bytes) > 64:
    raise ValueError("Profile nickname must be 64 bytes or less")
  content = encode_tlv(TAG_ICCID, string_to_tbcd(iccid)) + encode_tlv(0x90, nickname_bytes)
  code = _extract_status(es10x_command(client, encode_tlv(TAG_SET_NICKNAME, content)), TAG_SET_NICKNAME, "SetNickname")
  if code == 0x01:
    raise RuntimeError(f"profile {iccid} not found")
  if code != 0x00:
    raise RuntimeError(f"SetNickname failed with status 0x{code:02X}")


# --- Notifications ---

def list_notifications(client: AtClient) -> list[dict]:
  response = es10x_command(client, encode_tlv(TAG_LIST_NOTIFICATION, b""))
  root = find_tag(response, TAG_LIST_NOTIFICATION)
  if root is None:
    raise RuntimeError("Missing ListNotificationResponse")
  metadata_list = find_tag(root, 0xA0)
  if metadata_list is None:
    return []
  notifications: list[dict] = []
  for tag, value in iter_tlv(metadata_list):
    if tag != TAG_NOTIFICATION_METADATA:
      continue
    notification = {"seqNumber": None, "profileManagementOperation": None, "notificationAddress": None, "iccid": None}
    for t, v in iter_tlv(value):
      if t == TAG_STATUS and len(v) > 0:
        notification["seqNumber"] = int.from_bytes(v, "big")
      elif t == 0x81 and len(v) >= 2:
        notification["profileManagementOperation"] = next((m for m in [0x80, 0x40, 0x20, 0x10] if v[1] & m), 0xFF)
      elif t == 0x0C:
        notification["notificationAddress"] = v.decode("utf-8", errors="ignore")
      elif t == TAG_ICCID:
        notification["iccid"] = tbcd_to_string(v)
    if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"]:
      notifications.append(notification)
  return notifications


def retrieve_notifications_list(client: AtClient, seq_number: int) -> dict:
  request = encode_tlv(TAG_RETRIEVE_NOTIFICATION, encode_tlv(0xA0, encode_tlv(TAG_STATUS, _int_bytes(seq_number))))
  response = es10x_command(client, request)
  root = find_tag(response, TAG_RETRIEVE_NOTIFICATION)
  if root is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse")
  a0_content = find_tag(root, 0xA0)
  if a0_content is None:
    raise RuntimeError("Invalid RetrieveNotificationsListResponse")
  pending_notif, pending_tag = None, None
  for tag, value in iter_tlv(a0_content):
    if tag in (TAG_PROFILE_INSTALL_RESULT, 0x30):
      pending_notif, pending_tag = value, tag
      break
  if pending_notif is None:
    raise RuntimeError("Missing PendingNotification")
  if pending_tag == TAG_PROFILE_INSTALL_RESULT:
    result_data = find_tag(pending_notif, 0xBF27)
    notif_meta = find_tag(result_data, TAG_NOTIFICATION_METADATA) if result_data else None
  else:
    notif_meta = find_tag(pending_notif, TAG_NOTIFICATION_METADATA)
  if notif_meta is None:
    raise RuntimeError("Missing NotificationMetadata")
  addr = find_tag(notif_meta, 0x0C)
  if addr is None:
    raise RuntimeError("Missing notificationAddress")
  return {"notificationAddress": addr.decode("utf-8", errors="ignore"), "b64_PendingNotification": base64.b64encode(pending_notif).decode("ascii")}


def es10b_remove_notification_from_list(client: AtClient, seq_number: int) -> None:
  response = es10x_command(client, encode_tlv(TAG_NOTIFICATION_SENT, encode_tlv(TAG_STATUS, _int_bytes(seq_number))))
  root = find_tag(response, TAG_NOTIFICATION_SENT)
  if root is None:
    raise RuntimeError("Invalid NotificationSentResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None or int.from_bytes(status, "big") != 0:
    raise RuntimeError("RemoveNotificationFromList failed")


def process_notifications(client: AtClient) -> None:
  notifications = list_notifications(client)
  if not notifications:
    print("No notifications to process", file=sys.stderr)
    return
  print(f"Found {len(notifications)} notification(s) to process", file=sys.stderr)
  for notification in notifications:
    seq_number, smdp_address = notification["seqNumber"], notification["notificationAddress"]
    if not seq_number or not smdp_address:
      continue
    print(f"Processing notification seqNumber={seq_number}, address={smdp_address}", file=sys.stderr)
    try:
      notif_data = retrieve_notifications_list(client, seq_number)
      es9p_request(smdp_address, "handleNotification", {"pendingNotification": notif_data["b64_PendingNotification"]}, "HandleNotification")
      es10b_remove_notification_from_list(client, seq_number)
      print(f"Notification {seq_number} processed successfully", file=sys.stderr)
    except Exception as e:
      print(f"Failed to process notification {seq_number}: {e}", file=sys.stderr)


# --- Authentication & Download ---

def es10b_get_euicc_challenge_and_info(client: AtClient) -> tuple[bytes, bytes]:
  challenge_resp = es10x_command(client, encode_tlv(TAG_EUICC_CHALLENGE, b""))
  root = find_tag(challenge_resp, TAG_EUICC_CHALLENGE)
  if root is None:
    raise RuntimeError("Missing GetEuiccDataResponse")
  challenge = find_tag(root, TAG_STATUS)
  if challenge is None:
    raise RuntimeError("Missing challenge in response")
  info_resp = es10x_command(client, encode_tlv(TAG_EUICC_INFO, b""))
  if not info_resp.startswith(bytes([0xBF, 0x20])):
    raise RuntimeError("Missing GetEuiccInfo1Response")
  return challenge, info_resp


def build_authenticate_server_request(server_signed1: bytes, server_signature1: bytes, euicc_ci_pk_id: bytes, server_certificate: bytes) -> bytes:
  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = encode_tlv(TAG_STATUS, tac) + encode_tlv(0xA1, b"")
  content = server_signed1 + server_signature1 + euicc_ci_pk_id + server_certificate + encode_tlv(0xA0, encode_tlv(0xA1, device_info))
  return encode_tlv(TAG_AUTH_SERVER, content)


def es10b_authenticate_server_r(client: AtClient, b64_signed1: str, b64_sig1: str, b64_pk_id: str, b64_cert: str) -> str:
  request = build_authenticate_server_request(
    base64.b64decode(b64_signed1), base64.b64decode(b64_sig1), base64.b64decode(b64_pk_id), base64.b64decode(b64_cert))
  response = es10x_command(client, request)
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse")
  return base64.b64encode(response).decode("ascii")


def es10b_prepare_download_r(client: AtClient, b64_signed2: str, b64_sig2: str, b64_cert: str, cc: str | None = None) -> str:
  smdp_signed2 = base64.b64decode(b64_signed2)
  smdp_signature2 = base64.b64decode(b64_sig2)
  smdp_certificate = base64.b64decode(b64_cert)
  smdp_signed2_root = find_tag(smdp_signed2, 0x30)
  if smdp_signed2_root is None:
    raise RuntimeError("Invalid smdpSigned2")
  transaction_id = find_tag(smdp_signed2_root, TAG_STATUS)
  cc_required_flag = find_tag(smdp_signed2_root, 0x01)
  if transaction_id is None or cc_required_flag is None:
    raise RuntimeError("Invalid smdpSigned2")
  content = smdp_signed2 + smdp_signature2
  if int.from_bytes(cc_required_flag, "big") != 0:
    if not cc:
      raise RuntimeError("Confirmation code required but not provided")
    content += encode_tlv(0x04, hashlib.sha256(hashlib.sha256(cc.encode("utf-8")).digest() + transaction_id).digest())
  content += smdp_certificate
  response = es10x_command(client, encode_tlv(TAG_PREPARE_DOWNLOAD, content))
  if not response.startswith(bytes([0xBF, 0x21])):
    raise RuntimeError("Invalid PrepareDownloadResponse")
  return base64.b64encode(response).decode("ascii")


def _parse_tlv_header_len(data: bytes) -> int:
  """Return the combined tag + length header size for a TLV element."""
  tag_len = 2 if data[0] & 0x1F == 0x1F else 1
  length_byte = data[tag_len]
  return tag_len + (1 + (length_byte & 0x7F) if length_byte & 0x80 else 1)


def es10b_load_bound_profile_package_r(client: AtClient, b64_bpp: str) -> dict:
  bpp = base64.b64decode(b64_bpp)
  if not bpp.startswith(bytes([0xBF, 0x36])):
    raise RuntimeError("Invalid BoundProfilePackage")

  bpp_root_value, bpp_value_start = None, 0
  for tag, value, start, end in iter_tlv(bpp, with_positions=True):
    if tag == TAG_BPP:
      bpp_root_value = value
      bpp_value_start = start + _parse_tlv_header_len(bpp[start:end])
      break
  if bpp_root_value is None:
    raise RuntimeError("Invalid BoundProfilePackage")

  # Build chunks for sequential sending
  chunks = []
  # Chunk 1: BF36 header + BF23 (initialiseSecureChannelResponse)
  for tag, _, _, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xBF23:
      chunks.append(bpp[0 : bpp_value_start + end])
      break
  # Extract remaining segments: A0, A1, A2, A3
  for tag, value, start, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xA0:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])
    elif tag in (0xA1, 0xA3):
      # Send tag+length header, then children separately
      hdr_len = _parse_tlv_header_len(bpp_root_value[start:end])
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + start + hdr_len])
      for child_tag, child_value in iter_tlv(value):
        chunks.append(encode_tlv(child_tag, child_value))
    elif tag == 0xA2:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])

  result = {"seqNumber": 0, "success": False, "bppCommandId": None, "errorReason": None}
  for chunk in chunks:
    response = es10x_command(client, chunk)
    if not response:
      continue
    root = find_tag(response, TAG_PROFILE_INSTALL_RESULT)
    if not root:
      continue
    result_data = find_tag(root, 0xBF27)
    if not result_data:
      continue
    notif_meta = find_tag(result_data, TAG_NOTIFICATION_METADATA)
    if notif_meta:
      seq_num = find_tag(notif_meta, TAG_STATUS)
      if seq_num:
        result["seqNumber"] = int.from_bytes(seq_num, "big")
    final_result = find_tag(result_data, 0xA2)
    if final_result:
      for tag, value in iter_tlv(final_result):
        if tag == 0xA0:
          result["success"] = True
        elif tag == 0xA1:
          bpp_cmd = find_tag(value, TAG_STATUS)
          if bpp_cmd:
            result["bppCommandId"] = int.from_bytes(bpp_cmd, "big")
          err = find_tag(value, 0x81)
          if err:
            result["errorReason"] = int.from_bytes(err, "big")
  if not result["success"] and result["errorReason"] is not None:
    raise RuntimeError(f"Profile installation failed: bppCommandId={result['bppCommandId']}, errorReason={result['errorReason']}")
  return result


def es8p_metadata_parse(b64_metadata: str) -> dict:
  root = find_tag(base64.b64decode(b64_metadata), 0xBF25)
  if root is None:
    raise RuntimeError("Invalid profileMetadata")
  defaults = {"iccid": None, "serviceProviderName": None, "profileName": None, "iconType": None, "icon": None, "profileClass": None}
  return {**defaults, **_decode_profile_fields(root)}


def parse_lpa_activation_code(activation_code: str) -> tuple[str, str, str]:
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def download_profile(client: AtClient, activation_code: str) -> None:
  _, smdp, matching_id = parse_lpa_activation_code(activation_code)
  challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)
  b64_chal = base64.b64encode(challenge).decode("ascii")
  b64_info = base64.b64encode(euicc_info).decode("ascii")

  payload = {"smdpAddress": smdp, "euiccChallenge": b64_chal, "euiccInfo1": b64_info}
  if matching_id:
    payload["matchingId"] = matching_id
  auth = es9p_request(smdp, "initiateAuthentication", payload, "Authentication")
  b64_auth_resp = es10b_authenticate_server_r(
    client, base64_trim(auth.get("serverSigned1", "")), base64_trim(auth.get("serverSignature1", "")),
    base64_trim(auth.get("euiccCiPKIdToBeUsed", "")), base64_trim(auth.get("serverCertificate", "")))

  tx_id = base64_trim(auth.get("transactionId", ""))
  cli = es9p_request(smdp, "authenticateClient", {"transactionId": tx_id, "authenticateServerResponse": b64_auth_resp}, "Authentication")
  metadata = es8p_metadata_parse(base64_trim(cli.get("profileMetadata", "")))
  print(f'Downloading profile: {metadata["iccid"]} - {metadata["serviceProviderName"]} - {metadata["profileName"]}')

  b64_prep = es10b_prepare_download_r(
    client, base64_trim(cli.get("smdpSigned2", "")), base64_trim(cli.get("smdpSignature2", "")), base64_trim(cli.get("smdpCertificate", "")))
  bpp = es9p_request(smdp, "getBoundProfilePackage", {"transactionId": tx_id, "prepareDownloadResponse": b64_prep}, "GetBoundProfilePackage")

  result = es10b_load_bound_profile_package_r(client, base64_trim(bpp.get("boundProfilePackage", "")))
  if result["success"]:
    print(f"Profile installed successfully (seqNumber: {result['seqNumber']})")
  else:
    raise RuntimeError(f"Profile installation failed: {result}")


# --- CLI ---

def build_cli() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Minimal AT-only LPA implementation")
  parser.add_argument("--device", default=DEFAULT_DEVICE)
  parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
  parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
  parser.add_argument("--verbose", action="store_true")
  parser.add_argument("--enable", type=str)
  parser.add_argument("--disable", type=str)
  parser.add_argument("--no-refresh", action="store_true", help="Skip REFRESH after enable/disable")
  parser.add_argument("--set-nickname", nargs=2, metavar=("ICCID", "NICKNAME"))
  parser.add_argument("--list-notifications", action="store_true")
  parser.add_argument("--process-notifications", action="store_true")
  parser.add_argument("--download", type=str, metavar="CODE")
  return parser


def main() -> None:
  args = build_cli().parse_args()

  # ModemManager grabs the AT port and interferes with APDU transport.
  # mask prevents D-Bus activation from restarting it while we work.
  mm_was_active = subprocess.run(
    ["systemctl", "is-active", "--quiet", "ModemManager"],
  ).returncode == 0
  subprocess.run(["sudo", "systemctl", "mask", "--runtime", "ModemManager"], check=True)
  if mm_was_active:
    subprocess.run(["sudo", "systemctl", "stop", "ModemManager"], check=True)

  try:
    client = AtClient(args.device, args.baud, args.timeout, args.verbose)
    try:
      client.ensure_capabilities()
      client.open_isdr()
      show_profiles = True
      if args.enable:
        enable_profile(client, args.enable, refresh=not args.no_refresh)
      elif args.disable:
        disable_profile(client, args.disable, refresh=not args.no_refresh)
      elif args.set_nickname:
        set_profile_nickname(client, args.set_nickname[0], args.set_nickname[1])
      elif args.list_notifications:
        print(json.dumps(list_notifications(client), indent=2))
        show_profiles = False
      elif args.process_notifications:
        process_notifications(client)
        show_profiles = False
      elif args.download:
        download_profile(client, args.download)
      if show_profiles:
        print(json.dumps(request_profile_info(client), indent=2))
    finally:
      client.close()
  finally:
    subprocess.run(["sudo", "systemctl", "unmask", "ModemManager"])
    if mm_was_active:
      subprocess.run(["sudo", "systemctl", "start", "ModemManager"])


if __name__ == "__main__":
  main()
