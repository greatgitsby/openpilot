#!/usr/bin/env python3

import argparse
import base64
import binascii
import hashlib
import json
import requests
import serial
import sys

from collections.abc import Generator
from typing import Optional


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
    raise RuntimeError("Failed to open ISD-R application")

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


def es10x_command(client: AtClient, data: bytes) -> bytes:
  response = bytearray()
  sequence = 0
  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + ES10X_MSS]
    offset += len(chunk)
    # STORE DATA command: 0x80=CLA, 0xE2=INS, P1=0x91(last)/0x11(more), P2=sequence
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


def iter_tlv(data: bytes, with_positions: bool = False) -> Generator:
  idx = 0
  length = len(data)
  while idx < length:
    start_pos = idx
    tag = data[idx]
    idx += 1
    if tag & 0x1F == 0x1F:  # Multi-byte tag
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
    if with_positions:
      yield tag_value, value, start_pos, idx
    else:
      yield tag_value, value


def find_tag(data: bytes, target: int) -> Optional[bytes]:
  for tag, value in iter_tlv(data):
    if tag == target:
      return value
  return None


def encode_tlv(tag: int, value: bytes) -> bytes:
  tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF]) if tag > 255 else bytes([tag])
  value_len = len(value)
  if value_len <= 127:
    return tag_bytes + bytes([value_len]) + value
  length_bytes = value_len.to_bytes((value_len.bit_length() + 7) // 8, "big")
  return tag_bytes + bytes([0x80 | len(length_bytes)]) + length_bytes + value


def tbcd_to_string(raw: bytes) -> str:
  digits: list[str] = []
  for byte in raw:
    low, high = byte & 0x0F, (byte >> 4) & 0x0F
    if low <= 9:
      digits.append(str(low))
    if high <= 9 and high != 0x0F:
      digits.append(str(high))
  return "".join(digits)


def string_to_tbcd(s: str) -> bytes:
  # TBCD: each byte = low nibble first digit, high nibble second digit (or 0xF filler)
  result = bytearray()
  digits = [int(c) for c in s if c.isdigit()]
  for i in range(0, len(digits), 2):
    if i + 1 < len(digits):
      result.append(digits[i] | (digits[i + 1] << 4))
    else:
      result.append(digits[i] | 0xF0)
  return bytes(result)


def base64_trim(s: str) -> str:
  return "".join(c for c in s if c not in "\n\r \t")


# ES9P HTTP helpers
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


# Generic profile command helpers
def build_iccid_request(tag: int, iccid: str, extra_tlvs: list[tuple[int, bytes]] = None) -> bytes:
  content = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
  for t, v in (extra_tlvs or []):
    content += encode_tlv(t, v)
  return encode_tlv(tag, content)


def execute_profile_command(client: AtClient, tag: int, iccid: str, extra_tlvs=None, cmd_name: str = "Command") -> int:
  response = es10x_command(client, build_iccid_request(tag, iccid, extra_tlvs))
  root = find_tag(response, tag)
  if root is None:
    raise RuntimeError(f"Missing {cmd_name} response")
  status = find_tag(root, TAG_STATUS)
  if status is None:
    raise RuntimeError(f"Missing status in {cmd_name} response")
  return status[0]


def decode_profiles(blob: bytes) -> list[dict]:
  root = find_tag(blob, TAG_PROFILE_INFO_LIST)
  if root is None:
    raise RuntimeError("Missing ProfileInfoList")
  list_ok = find_tag(root, 0xA0)
  if list_ok is None:
    return []
  profiles: list[dict] = []
  for tag, value in iter_tlv(list_ok):
    if tag != 0xE3:
      continue
    profile: dict = {"iccid": None, "isdpAid": None, "profileState": None, "profileNickname": None,
                     "serviceProviderName": None, "profileName": None, "iconType": None, "icon": None, "profileClass": None}
    for item_tag, item_value in iter_tlv(value):
      if item_tag == TAG_ICCID:
        profile["iccid"] = tbcd_to_string(item_value)
      elif item_tag == 0x4F:
        profile["isdpAid"] = item_value.hex().upper()
      elif item_tag == 0x9F70:
        profile["profileState"] = STATE_LABELS.get(int.from_bytes(item_value, "big"), "unknown")
      elif item_tag == 0x90:
        profile["profileNickname"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x91:
        profile["serviceProviderName"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x92:
        profile["profileName"] = item_value.decode("utf-8", errors="ignore") or None
      elif item_tag == 0x93:
        profile["iconType"] = ICON_LABELS.get(int.from_bytes(item_value, "big"), "unknown")
      elif item_tag == 0x94:
        profile["icon"] = base64.b64encode(item_value).decode("ascii")
      elif item_tag == 0x95:
        profile["profileClass"] = CLASS_LABELS.get(int.from_bytes(item_value, "big"), "unknown")
    profiles.append(profile)
  return profiles


def request_profile_info(client: AtClient) -> list[dict]:
  return decode_profiles(es10x_command(client, bytes.fromhex("BF2D00")))


def enable_profile(client: AtClient, iccid: str) -> None:
  # Build with A0 wrapper: BF31 [A0 [5A iccid]]
  content = encode_tlv(0xA0, encode_tlv(TAG_ICCID, string_to_tbcd(iccid)))
  response = es10x_command(client, encode_tlv(TAG_ENABLE_PROFILE, content))
  root = find_tag(response, TAG_ENABLE_PROFILE)
  if root is None:
    raise RuntimeError("Missing EnableProfileResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None:
    raise RuntimeError("Missing status in EnableProfileResponse")
  code = status[0]
  if code == 0x01:
    raise RuntimeError(f"profile {iccid} not found")
  elif code == 0x02:
    print(f"profile {iccid} already enabled")
  elif code != 0x00:
    raise RuntimeError(f"EnableProfile failed with status 0x{code:02X}")


def disable_profile(client: AtClient, iccid: str) -> None:
  content = encode_tlv(0xA0, encode_tlv(TAG_ICCID, string_to_tbcd(iccid)))
  response = es10x_command(client, encode_tlv(TAG_DISABLE_PROFILE, content))
  root = find_tag(response, TAG_DISABLE_PROFILE)
  if root is None:
    raise RuntimeError("Missing DisableProfileResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None:
    raise RuntimeError("Missing status in DisableProfileResponse")
  code = status[0]
  if code == 0x01:
    raise RuntimeError(f"profile {iccid} not found")
  elif code == 0x02:
    print(f"profile {iccid} already disabled")
  elif code != 0x00:
    raise RuntimeError(f"DisableProfile failed with status 0x{code:02X}")


def set_profile_nickname(client: AtClient, iccid: str, nickname: str) -> None:
  nickname_bytes = nickname.encode("utf-8")
  if len(nickname_bytes) > 64:
    raise ValueError("Profile nickname must be 64 bytes or less")
  content = encode_tlv(TAG_ICCID, string_to_tbcd(iccid)) + encode_tlv(0x90, nickname_bytes)
  response = es10x_command(client, encode_tlv(TAG_SET_NICKNAME, content))
  root = find_tag(response, TAG_SET_NICKNAME)
  if root is None:
    raise RuntimeError("Missing SetNicknameResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None:
    raise RuntimeError("Missing status in SetNicknameResponse")
  code = status[0]
  if code == 0x01:
    raise RuntimeError(f"profile {iccid} not found")
  elif code != 0x00:
    raise RuntimeError(f"SetNickname failed with status 0x{code:02X}")


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
      elif t == 0x81 and len(v) >= 2:  # profileManagementOperation bitstring
        bit_data = v[1]
        # Bit 0=INSTALL(0x80), 1=ENABLE(0x40), 2=DISABLE(0x20), 3=DELETE(0x10)
        notification["profileManagementOperation"] = next((m for m in [0x80, 0x40, 0x20, 0x10] if bit_data & m), 0xFF)
      elif t == 0x0C:
        notification["notificationAddress"] = v.decode("utf-8", errors="ignore")
      elif t == TAG_ICCID:
        notification["iccid"] = tbcd_to_string(v)
    if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"]:
      notifications.append(notification)
  return notifications


def retrieve_notifications_list(client: AtClient, seq_number: int) -> dict:
  seq_bytes = seq_number.to_bytes((seq_number.bit_length() + 7) // 8 or 1, "big")
  request = encode_tlv(TAG_RETRIEVE_NOTIFICATION, encode_tlv(0xA0, encode_tlv(TAG_STATUS, seq_bytes)))
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
  notif_meta = None
  if pending_tag == TAG_PROFILE_INSTALL_RESULT:
    result_data = find_tag(pending_notif, 0xBF27)
    if result_data:
      notif_meta = find_tag(result_data, TAG_NOTIFICATION_METADATA)
  else:
    notif_meta = find_tag(pending_notif, TAG_NOTIFICATION_METADATA)
  if notif_meta is None:
    raise RuntimeError("Missing NotificationMetadata")
  addr = find_tag(notif_meta, 0x0C)
  if addr is None:
    raise RuntimeError("Missing notificationAddress")
  return {"notificationAddress": addr.decode("utf-8", errors="ignore"), "b64_PendingNotification": base64.b64encode(pending_notif).decode("ascii")}


def es10b_remove_notification_from_list(client: AtClient, seq_number: int) -> None:
  seq_bytes = seq_number.to_bytes((seq_number.bit_length() + 7) // 8 or 1, "big")
  response = es10x_command(client, encode_tlv(TAG_NOTIFICATION_SENT, encode_tlv(TAG_STATUS, seq_bytes)))
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
  # TAC (Type Allocation Code) - device identifier
  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = encode_tlv(TAG_STATUS, tac) + encode_tlv(0xA1, b"")
  ctx_params = encode_tlv(0xA1, device_info)
  content = server_signed1 + server_signature1 + euicc_ci_pk_id + server_certificate + encode_tlv(0xA0, ctx_params)
  return encode_tlv(TAG_AUTH_SERVER, content)


def es10b_authenticate_server_r(client: AtClient, b64_signed1: str, b64_sig1: str, b64_pk_id: str, b64_cert: str) -> str:
  request = build_authenticate_server_request(
    base64.b64decode(b64_signed1), base64.b64decode(b64_sig1), base64.b64decode(b64_pk_id), base64.b64decode(b64_cert))
  response = es10x_command(client, request)
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse")
  return base64.b64encode(response).decode("ascii")


def es10b_prepare_download_r(client: AtClient, b64_signed2: str, b64_sig2: str, b64_cert: str, cc: Optional[str] = None) -> str:
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
    hash1 = hashlib.sha256(cc.encode("utf-8")).digest()
    content += encode_tlv(0x04, hashlib.sha256(hash1 + transaction_id).digest())
  content += smdp_certificate
  response = es10x_command(client, encode_tlv(TAG_PREPARE_DOWNLOAD, content))
  if not response.startswith(bytes([0xBF, 0x21])):
    raise RuntimeError("Invalid PrepareDownloadResponse")
  return base64.b64encode(response).decode("ascii")


def es10b_load_bound_profile_package_r(client: AtClient, b64_bpp: str) -> dict:
  bpp = base64.b64decode(b64_bpp)
  if not bpp.startswith(bytes([0xBF, 0x36])):
    raise RuntimeError("Invalid BoundProfilePackage")

  # Parse BPP structure and extract chunks for sequential sending
  bpp_root_value, bpp_value_start = None, 0
  for tag, value, start, end in iter_tlv(bpp, with_positions=True):
    if tag == TAG_BPP:
      bpp_root_value = value
      bf36_data = bpp[start:end]
      tag_len = 2
      length_byte = bf36_data[tag_len]
      length_len = 1 + (length_byte & 0x7F) if length_byte & 0x80 else 1
      bpp_value_start = start + tag_len + length_len
      break
  if bpp_root_value is None:
    raise RuntimeError("Invalid BoundProfilePackage")

  chunks = []
  # Chunk 1: BF36 header + BF23 (initialiseSecureChannelResponse)
  for tag, _, _, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xBF23:
      chunks.append(bpp[0 : bpp_value_start + end])
      break
  # Extract A0, A1, A2, A3 tags
  for tag, value, start, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xA0:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])
    elif tag in (0xA1, 0xA3):
      # Send tag+length header, then children separately
      data = bpp_root_value[start:end]
      tag_len = 2 if data[0] & 0x1F == 0x1F else 1
      length_byte = data[tag_len]
      length_len = 1 + (length_byte & 0x7F) if length_byte & 0x80 else 1
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + start + tag_len + length_len])
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
    if root:
      result_data = find_tag(root, 0xBF27)
      if result_data:
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
  metadata = base64.b64decode(b64_metadata)
  root = find_tag(metadata, 0xBF25)  # StoreMetadataRequest
  if root is None:
    raise RuntimeError("Invalid profileMetadata")
  result = {"iccid": None, "serviceProviderName": None, "profileName": None, "iconType": None, "icon": None, "profileClass": None}
  for tag, value in iter_tlv(root):
    if tag == TAG_ICCID:
      result["iccid"] = tbcd_to_string(value)
    elif tag == 0x91:
      result["serviceProviderName"] = value.decode("utf-8", errors="ignore") or None
    elif tag == 0x92:
      result["profileName"] = value.decode("utf-8", errors="ignore") or None
    elif tag == 0x93:
      result["iconType"] = ICON_LABELS.get(int.from_bytes(value, "big"), "unknown")
    elif tag == 0x94:
      result["icon"] = base64.b64encode(value).decode("ascii")
    elif tag == 0x95:
      result["profileClass"] = CLASS_LABELS.get(int.from_bytes(value, "big"), "unknown")
  return result


def parse_lpa_activation_code(activation_code: str) -> tuple[str, str, str]:
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def download_profile(client: AtClient, activation_code: str) -> None:
  _, smdp, _ = parse_lpa_activation_code(activation_code)
  challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)
  b64_chal = base64.b64encode(challenge).decode("ascii")
  b64_info = base64.b64encode(euicc_info).decode("ascii")

  auth = es9p_request(smdp, "initiateAuthentication",
                      {"smdpAddress": smdp, "euiccChallenge": b64_chal, "euiccInfo1": b64_info}, "Authentication")
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


def build_cli() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Minimal AT-only LPA implementation")
  parser.add_argument("--device", default=DEFAULT_DEVICE)
  parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
  parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
  parser.add_argument("--verbose", action="store_true")
  parser.add_argument("--enable", type=str)
  parser.add_argument("--disable", type=str)
  parser.add_argument("--set-nickname", nargs=2, metavar=("ICCID", "NICKNAME"))
  parser.add_argument("--list-notifications", action="store_true")
  parser.add_argument("--process-notifications", action="store_true")
  parser.add_argument("--download", type=str, metavar="CODE")
  return parser


def main() -> None:
  args = build_cli().parse_args()
  client = AtClient(args.device, args.baud, args.timeout, args.verbose)
  try:
    client.ensure_capabilities()
    client.open_isdr()
    if args.enable:
      enable_profile(client, args.enable)
      print(json.dumps(request_profile_info(client), indent=2))
    elif args.disable:
      disable_profile(client, args.disable)
      print(json.dumps(request_profile_info(client), indent=2))
    elif args.set_nickname:
      set_profile_nickname(client, args.set_nickname[0], args.set_nickname[1])
      print(json.dumps(request_profile_info(client), indent=2))
    elif args.list_notifications:
      print(json.dumps(list_notifications(client), indent=2))
    elif args.process_notifications:
      process_notifications(client)
    elif args.download:
      download_profile(client, args.download)
      print(json.dumps(request_profile_info(client), indent=2))
    else:
      print(json.dumps(request_profile_info(client), indent=2))
  finally:
    client.close()


if __name__ == "__main__":
  main()
