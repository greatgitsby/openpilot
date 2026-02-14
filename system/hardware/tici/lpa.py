#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import logging
import requests
import serial
import sys

from collections.abc import Generator

log = logging.getLogger("lpa")


DEFAULT_DEVICE = "/dev/ttyUSB2"
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
TAG_DELETE_PROFILE = 0xBF33
TAG_BPP = 0xBF36
TAG_PROFILE_INSTALL_RESULT = 0xBF37
TAG_AUTH_SERVER = 0xBF38
TAG_CANCEL_SESSION = 0xBF41

STATE_LABELS = {0: "disabled", 1: "enabled", 255: "unknown"}
ICON_LABELS = {0: "jpeg", 1: "png", 255: "unknown"}
CLASS_LABELS = {0: "test", 1: "provisioning", 2: "operational", 255: "unknown"}
PROFILE_ERROR_CODES = {
  0x01: "iccidOrAidNotFound", 0x02: "profileNotInDisabledState",
  0x03: "disallowedByPolicy", 0x04: "wrongProfileReenabling",
  0x05: "catBusy", 0x06: "undefinedError",
}
AUTH_SERVER_ERROR_CODES = {
  0x01: "eUICCVerificationFailed", 0x02: "eUICCCertificateExpired",
  0x03: "eUICCCertificateRevoked", 0x05: "invalidServerSignature",
  0x06: "euiccCiPKUnknown", 0x0A: "matchingIdRefused",
  0x10: "insufficientMemory",
}
BPP_COMMAND_NAMES = {
  0: "initialiseSecureChannel", 1: "configureISDP", 2: "storeMetadata",
  3: "storeMetadata2", 4: "replaceSessionKeys", 5: "loadProfileElements",
}
BPP_ERROR_REASONS = {
  1: "incorrectInputValues", 2: "invalidSignature", 3: "invalidTransactionId",
  4: "unsupportedCrtValues", 5: "unsupportedRemoteOperationType",
  6: "unsupportedProfileClass", 7: "scp03tStructureError", 8: "scp03tSecurityError",
  9: "iccidAlreadyExistsOnEuicc", 10: "insufficientMemoryForProfile",
  11: "installInterrupted", 12: "peProcessingError", 13: "dataMismatch",
  14: "invalidNAA",
}
CANCEL_SESSION_REASON = {
  0: "endUserRejection", 1: "postponed", 2: "timeout",
  3: "pprNotAllowed", 127: "undefinedReason",
}


class AtClient:
  def __init__(self, device: str, baud: int, timeout: float, verbose: bool) -> None:
    log.debug("opening serial %s baud=%d timeout=%.1f", device, baud, timeout)
    self.ser = serial.Serial(device, baudrate=baud, timeout=timeout)
    self.verbose = verbose
    self.channel: str | None = None
    self.ser.reset_input_buffer()
    log.debug("serial port opened successfully")

  def close(self) -> None:
    log.debug("closing AT client (channel=%s)", self.channel)
    try:
      if self.channel:
        self.query(f"AT+CCHC={self.channel}")
        self.channel = None
    finally:
      self.ser.close()
      log.debug("serial port closed")

  def send(self, cmd: str) -> None:
    if self.verbose:
      print(f">> {cmd}", file=sys.stderr)
    log.debug("AT TX >> %s", cmd)
    self.ser.write((cmd + "\r").encode("ascii"))

  def expect(self) -> list[str]:
    lines: list[str] = []
    while True:
      raw = self.ser.readline()
      if not raw:
        log.debug("AT RX timed out after reading %d line(s)", len(lines))
        raise TimeoutError("AT command timed out")
      line = raw.decode(errors="ignore").strip()
      if not line:
        continue
      if self.verbose:
        print(f"<< {line}", file=sys.stderr)
      log.debug("AT RX << %s", line)
      if line == "OK":
        return lines
      if line == "ERROR":
        log.debug("AT command returned ERROR, lines so far: %s", lines)
        raise RuntimeError("AT command failed")
      lines.append(line)

  def query(self, cmd: str) -> list[str]:
    self.send(cmd)
    resp = self.expect()
    log.debug("AT query %r -> %d response line(s)", cmd, len(resp))
    return resp

  def ensure_capabilities(self) -> None:
    log.debug("checking modem AT capabilities")
    self.query("AT")
    for command in ("AT+CCHO", "AT+CCHC", "AT+CGLA"):
      self.query(f"{command}=?")
    log.debug("modem capabilities verified")

  def open_isdr(self) -> None:
    log.debug("opening ISD-R channel (AID=%s)", ISDR_AID)
    for line in self.query(f'AT+CCHO="{ISDR_AID}"'):
      if line.startswith("+CCHO:") and (ch := line.split(":", 1)[1].strip()):
        self.channel = ch
        log.debug("ISD-R channel opened: %s", ch)
        return
    raise RuntimeError("Failed to open ISD-R application")

  def send_apdu(self, apdu: bytes) -> tuple[bytes, int, int]:
    if not self.channel:
      raise RuntimeError("Logical channel is not open")
    hex_payload = apdu.hex().upper()
    log.debug("APDU >> ch=%s len=%d data=%s", self.channel, len(hex_payload), hex_payload)
    for line in self.query(f'AT+CGLA={self.channel},{len(hex_payload)},"{hex_payload}"'):
      if line.startswith("+CGLA:"):
        parts = line.split(":", 1)[1].split(",", 1)
        if len(parts) == 2:
          data = bytes.fromhex(parts[1].strip().strip('"'))
          if len(data) >= 2:
            payload, sw1, sw2 = data[:-2], data[-2], data[-1]
            log.debug("APDU << SW=%02X%02X payload(%d bytes)=%s", sw1, sw2, len(payload), payload.hex().upper())
            return payload, sw1, sw2
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
  log.debug("es10x_command: sending %d bytes, tag=0x%s", len(data), data[:2].hex().upper() if len(data) >= 2 else data.hex().upper())
  response = bytearray()
  sequence = 0
  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + ES10X_MSS]
    offset += len(chunk)
    is_last = offset == len(data)
    # STORE DATA: CLA=0x80, INS=0xE2, P1=0x91(last)/0x11(more), P2=sequence
    apdu = bytes([0x80, 0xE2, 0x91 if is_last else 0x11, sequence & 0xFF, len(chunk)]) + chunk
    log.debug("  STORE DATA seq=%d %s chunk=%d bytes", sequence, "LAST" if is_last else "MORE", len(chunk))
    segment, sw1, sw2 = client.send_apdu(apdu)
    response.extend(segment)
    get_response_count = 0
    while True:
      if sw1 == 0x61:  # More data available
        get_response_count += 1
        log.debug("  GET RESPONSE #%d (SW2=0x%02X)", get_response_count, sw2)
        segment, sw1, sw2 = client.send_apdu(bytes([0x80, 0xC0, 0x00, 0x00, sw2 or 0]))
        response.extend(segment)
        continue
      if (sw1 & 0xF0) == 0x90:
        break
      raise RuntimeError(f"APDU failed with SW={sw1:02X}{sw2:02X}")
    sequence += 1
  log.debug("es10x_command: received %d bytes response", len(response))
  return bytes(response)


# --- ES9P HTTP ---

def es9p_request(smdp_address: str, endpoint: str, payload: dict, error_prefix: str = "Request") -> dict:
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/{endpoint}"
  log.debug("ES9+ POST %s (payload keys: %s)", url, list(payload.keys()))
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  log.debug("ES9+ response: HTTP %d, %d bytes", resp.status_code, len(resp.content))
  resp.raise_for_status()
  if not resp.content:
    return {}
  data = resp.json()
  log.debug("ES9+ response keys: %s", list(data.keys()))
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    log.debug("ES9+ functionExecutionStatus: %s", status.get("status"))
    if status.get("status") == "Failed":
      sd = status.get("statusCodeData", {})
      log.debug("ES9+ error details: %s", sd)
      raise RuntimeError(f"{error_prefix} failed: {sd.get('reasonCode', 'unknown')}/{sd.get('subjectCode', 'unknown')} - {sd.get('message', 'unknown')}")
  return data


# --- Profile operations ---

def decode_profiles(blob: bytes) -> list[dict]:
  log.debug("decode_profiles: parsing %d bytes", len(blob))
  root = find_tag(blob, TAG_PROFILE_INFO_LIST)
  if root is None:
    raise RuntimeError("Missing ProfileInfoList")
  list_ok = find_tag(root, 0xA0)
  if list_ok is None:
    log.debug("decode_profiles: empty profile list")
    return []
  defaults = {name: None for name, _ in _PROFILE_FIELDS.values()}
  profiles = [{**defaults, **_decode_profile_fields(value)} for tag, value in iter_tlv(list_ok) if tag == 0xE3]
  log.debug("decode_profiles: found %d profile(s)", len(profiles))
  for p in profiles:
    log.debug("  profile iccid=%s state=%s name=%s", p.get("iccid"), p.get("profileState"), p.get("profileName"))
  return profiles


def request_profile_info(client: AtClient) -> list[dict]:
  log.debug("requesting profile info list")
  return decode_profiles(es10x_command(client, bytes.fromhex("BF2D00")))


def _toggle_profile(client: AtClient, tag: int, iccid: str, refresh: bool, action: str) -> None:
  log.debug("%s profile iccid=%s refresh=%s", action, iccid, refresh)
  inner = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
  if not refresh:
    inner += encode_tlv(0x81, b'\x00')
  code = _extract_status(es10x_command(client, encode_tlv(tag, encode_tlv(0xA0, inner))), tag, f"{action.capitalize()}Profile")
  log.debug("%s profile result: status=0x%02X", action, code)
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


def delete_profile(client: AtClient, iccid: str) -> None:
  inner = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
  code = _extract_status(
    es10x_command(client, encode_tlv(TAG_DELETE_PROFILE, encode_tlv(0xA0, inner))),
    TAG_DELETE_PROFILE, "DeleteProfile"
  )
  if code != 0x00:
    raise RuntimeError(
      f"DeleteProfile failed: {PROFILE_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})"
    )


def set_profile_nickname(client: AtClient, iccid: str, nickname: str) -> None:
  log.debug("set nickname iccid=%s nickname=%r", iccid, nickname)
  nickname_bytes = nickname.encode("utf-8")
  if len(nickname_bytes) > 64:
    raise ValueError("Profile nickname must be 64 bytes or less")
  content = encode_tlv(TAG_ICCID, string_to_tbcd(iccid)) + encode_tlv(0x90, nickname_bytes)
  code = _extract_status(es10x_command(client, encode_tlv(TAG_SET_NICKNAME, content)), TAG_SET_NICKNAME, "SetNickname")
  log.debug("set nickname result: status=0x%02X", code)
  if code == 0x01:
    raise RuntimeError(f"profile {iccid} not found")
  if code != 0x00:
    raise RuntimeError(f"SetNickname failed with status 0x{code:02X}")


# --- Notifications ---

def list_notifications(client: AtClient) -> list[dict]:
  log.debug("listing notifications")
  response = es10x_command(client, encode_tlv(TAG_LIST_NOTIFICATION, b""))
  root = find_tag(response, TAG_LIST_NOTIFICATION)
  if root is None:
    raise RuntimeError("Missing ListNotificationResponse")
  metadata_list = find_tag(root, 0xA0)
  if metadata_list is None:
    log.debug("no notifications present")
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
  log.debug("found %d notification(s)", len(notifications))
  for n in notifications:
    log.debug("  seq=%s op=0x%02X addr=%s iccid=%s", n["seqNumber"], n["profileManagementOperation"] or 0, n["notificationAddress"], n["iccid"])
  return notifications


def retrieve_notifications_list(client: AtClient, seq_number: int) -> dict:
  log.debug("retrieving notification seq=%d", seq_number)
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
      log.debug("  pending notification tag=0x%04X len=%d", tag, len(value))
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
  decoded_addr = addr.decode("utf-8", errors="ignore")
  log.debug("  notification address=%s", decoded_addr)
  return {"notificationAddress": decoded_addr, "b64_PendingNotification": base64.b64encode(pending_notif).decode("ascii")}


def es10b_remove_notification_from_list(client: AtClient, seq_number: int) -> None:
  log.debug("removing notification seq=%d", seq_number)
  response = es10x_command(client, encode_tlv(TAG_NOTIFICATION_SENT, encode_tlv(TAG_STATUS, _int_bytes(seq_number))))
  root = find_tag(response, TAG_NOTIFICATION_SENT)
  if root is None:
    raise RuntimeError("Invalid NotificationSentResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None or int.from_bytes(status, "big") != 0:
    raise RuntimeError("RemoveNotificationFromList failed")
  log.debug("notification seq=%d removed", seq_number)


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
      log.debug("notification %d failed: %s", seq_number, e, exc_info=True)
      print(f"Failed to process notification {seq_number}: {e}", file=sys.stderr)


# --- Authentication & Download ---

def es10b_get_euicc_challenge_and_info(client: AtClient) -> tuple[bytes, bytes]:
  log.debug("getting eUICC challenge")
  challenge_resp = es10x_command(client, encode_tlv(TAG_EUICC_CHALLENGE, b""))
  root = find_tag(challenge_resp, TAG_EUICC_CHALLENGE)
  if root is None:
    raise RuntimeError("Missing GetEuiccDataResponse")
  challenge = find_tag(root, TAG_STATUS)
  if challenge is None:
    raise RuntimeError("Missing challenge in response")
  log.debug("eUICC challenge: %d bytes", len(challenge))
  log.debug("getting eUICC info")
  info_resp = es10x_command(client, encode_tlv(TAG_EUICC_INFO, b""))
  if not info_resp.startswith(bytes([0xBF, 0x20])):
    raise RuntimeError("Missing GetEuiccInfo1Response")
  log.debug("eUICC info: %d bytes", len(info_resp))
  return challenge, info_resp


def build_authenticate_server_request(server_signed1: bytes, server_signature1: bytes, euicc_ci_pk_id: bytes, server_certificate: bytes, matching_id: str | None = None) -> bytes:
  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = encode_tlv(TAG_STATUS, tac) + encode_tlv(0xA1, b"")
  ctx_inner = b""
  if matching_id:
    ctx_inner += encode_tlv(TAG_STATUS, matching_id.encode("utf-8"))
  ctx_inner += encode_tlv(0xA1, device_info)
  content = server_signed1 + server_signature1 + euicc_ci_pk_id + server_certificate + encode_tlv(0xA0, ctx_inner)
  return encode_tlv(TAG_AUTH_SERVER, content)


def _check_authenticate_server_response(response: bytes) -> None:
  """Check AuthenticateServerResponse for eUICC-side errors before forwarding to SM-DP+."""
  root = find_tag(response, TAG_AUTH_SERVER)
  if root is None:
    return
  # error tag is context [1] primitive = 0xA1 in the response
  error_tag = find_tag(root, 0xA1)
  if error_tag is not None:
    code = int.from_bytes(error_tag, "big") if error_tag else 0
    desc = AUTH_SERVER_ERROR_CODES.get(code, "unknown")
    raise RuntimeError(f"AuthenticateServer rejected by eUICC: {desc} (0x{code:02X})")


def es10b_authenticate_server_r(client: AtClient, b64_signed1: str, b64_sig1: str, b64_pk_id: str, b64_cert: str, matching_id: str | None = None) -> str:
  log.debug("es10b authenticate server (matching_id=%s)", matching_id or "(none)")
  request = build_authenticate_server_request(
    base64.b64decode(b64_signed1), base64.b64decode(b64_sig1), base64.b64decode(b64_pk_id), base64.b64decode(b64_cert),
    matching_id=matching_id)
  log.debug("  request: %d bytes", len(request))
  response = es10x_command(client, request)
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse")
  log.debug("  response: %d bytes", len(response))
  _check_authenticate_server_response(response)
  return base64.b64encode(response).decode("ascii")


def es10b_prepare_download_r(client: AtClient, b64_signed2: str, b64_sig2: str, b64_cert: str, cc: str | None = None) -> str:
  log.debug("es10b prepare download (cc=%s)", "provided" if cc else "none")
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
  log.debug("  transaction_id=%s cc_required=%s", transaction_id.hex(), int.from_bytes(cc_required_flag, "big") != 0)
  content = smdp_signed2 + smdp_signature2
  if int.from_bytes(cc_required_flag, "big") != 0:
    if not cc:
      raise RuntimeError("Confirmation code required but not provided")
    content += encode_tlv(0x04, hashlib.sha256(hashlib.sha256(cc.encode("utf-8")).digest() + transaction_id).digest())
  content += smdp_certificate
  log.debug("  PrepareDownload request: %d bytes", len(content))
  response = es10x_command(client, encode_tlv(TAG_PREPARE_DOWNLOAD, content))
  if not response.startswith(bytes([0xBF, 0x21])):
    raise RuntimeError("Invalid PrepareDownloadResponse")
  log.debug("  PrepareDownload response: %d bytes", len(response))
  return base64.b64encode(response).decode("ascii")


def _parse_tlv_header_len(data: bytes) -> int:
  """Return the combined tag + length header size for a TLV element."""
  tag_len = 2 if data[0] & 0x1F == 0x1F else 1
  length_byte = data[tag_len]
  return tag_len + (1 + (length_byte & 0x7F) if length_byte & 0x80 else 1)


def es10b_load_bound_profile_package_r(client: AtClient, b64_bpp: str) -> dict:
  bpp = base64.b64decode(b64_bpp)
  log.debug("loading BPP: %d bytes", len(bpp))
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

  # Log BPP structure before splitting
  log.debug("BPP structure (top-level children of BF36, value_start=%d, value_len=%d):", bpp_value_start, len(bpp_root_value))
  total_children_bytes = 0
  for tag, value, start, end in iter_tlv(bpp_root_value, with_positions=True):
    child_count = sum(1 for _ in iter_tlv(value)) if tag in (0xA0, 0xA1, 0xA2, 0xA3) else 0
    log.debug("  tag=0x%04X pos=%d..%d len=%d (value=%d) children=%d",
              tag, start, end, end - start, len(value), child_count)
    total_children_bytes += end - start
  log.debug("  total children bytes: %d / %d (value len)", total_children_bytes, len(bpp_root_value))
  if total_children_bytes != len(bpp_root_value):
    log.debug("  WARNING: %d bytes unaccounted for in BF36 value!", len(bpp_root_value) - total_children_bytes)

  chunks = []
  for tag, _, _, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xBF23:
      chunks.append(bpp[0 : bpp_value_start + end])
      break
  for tag, value, start, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xA0:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])
    elif tag in (0xA1, 0xA3):
      hdr_len = _parse_tlv_header_len(bpp_root_value[start:end])
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + start + hdr_len])
      for _, _, child_start, child_end in iter_tlv(value, with_positions=True):
        chunks.append(value[child_start:child_end])
    elif tag == 0xA2:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])

  log.debug("BPP split into %d chunk(s):", len(chunks))
  for i, chunk in enumerate(chunks):
    tag_hex = chunk[:2].hex().upper() if len(chunk) >= 2 else chunk.hex().upper()
    log.debug("  chunk %d: %d bytes, starts with 0x%s", i + 1, len(chunk), tag_hex)
  result = {"seqNumber": 0, "success": False, "bppCommandId": None, "errorReason": None}
  for i, chunk in enumerate(chunks):
    log.debug("  sending BPP chunk %d/%d (%d bytes, tag=0x%s)", i + 1, len(chunks), len(chunk), chunk[:2].hex().upper() if len(chunk) >= 2 else chunk.hex().upper())
    response = es10x_command(client, chunk)
    if not response:
      log.debug("  chunk %d: empty response", i + 1)
      continue
    root = find_tag(response, TAG_PROFILE_INSTALL_RESULT)
    if not root:
      continue
    log.debug("  chunk %d: got ProfileInstallResult", i + 1)
    result_data = find_tag(root, 0xBF27)
    if not result_data:
      break
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
    break  # ProfileInstallResult received — eUICC session is finalized
  log.debug("BPP install result: %s", result)
  if not result["success"] and result["errorReason"] is not None:
    cmd_name = BPP_COMMAND_NAMES.get(result["bppCommandId"], f"unknown({result['bppCommandId']})")
    err_name = BPP_ERROR_REASONS.get(result["errorReason"], f"unknown({result['errorReason']})")
    raise RuntimeError(f"Profile installation failed at {cmd_name}: {err_name} (bppCommandId={result['bppCommandId']}, errorReason={result['errorReason']})")
  return result


def es8p_metadata_parse(b64_metadata: str) -> dict:
  root = find_tag(base64.b64decode(b64_metadata), 0xBF25)
  if root is None:
    raise RuntimeError("Invalid profileMetadata")
  defaults = {"iccid": None, "serviceProviderName": None, "profileName": None, "iconType": None, "icon": None, "profileClass": None}
  return {**defaults, **_decode_profile_fields(root)}


def es10b_cancel_session(client: AtClient, transaction_id: bytes, reason: int = 127) -> str:
  log.debug("cancelling session transaction_id=%s reason=%d (%s)", transaction_id.hex(), reason, CANCEL_SESSION_REASON.get(reason, "unknown"))
  content = encode_tlv(0x80, transaction_id) + encode_tlv(0x81, bytes([reason]))
  response = es10x_command(client, encode_tlv(TAG_CANCEL_SESSION, content))
  root = find_tag(response, TAG_CANCEL_SESSION)
  if root is None:
    log.debug("cancel session: no response (may already be cleaned up)")
    return base64.b64encode(response).decode("ascii")
  # success is tag A0, error is tag 0x81
  error = find_tag(root, 0x81)
  if error is not None:
    log.debug("cancel session eUICC error: %d (non-fatal, session may already be finalized)", int.from_bytes(error, "big"))
  else:
    success = find_tag(root, 0xA0)
    log.debug("cancel session result: %s", "ok" if success is not None else "unknown")
  return base64.b64encode(response).decode("ascii")


def parse_lpa_activation_code(activation_code: str) -> tuple[str, str, str]:
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def download_profile(client: AtClient, activation_code: str) -> None:
  _, smdp, matching_id = parse_lpa_activation_code(activation_code)
  log.debug("download_profile: smdp=%s matching_id=%s", smdp, matching_id or "(none)")

  log.debug("step 1/5: get eUICC challenge and info")
  challenge, euicc_info = es10b_get_euicc_challenge_and_info(client)
  b64_chal = base64.b64encode(challenge).decode("ascii")
  b64_info = base64.b64encode(euicc_info).decode("ascii")

  log.debug("step 2/5: initiate authentication with SM-DP+")
  payload = {"smdpAddress": smdp, "euiccChallenge": b64_chal, "euiccInfo1": b64_info}
  if matching_id:
    payload["matchingId"] = matching_id
  auth = es9p_request(smdp, "initiateAuthentication", payload, "Authentication")
  tx_id = base64_trim(auth.get("transactionId", ""))
  tx_id_bytes = base64.b64decode(tx_id) if tx_id else b""
  log.debug("  transactionId=%s", tx_id)

  try:
    log.debug("step 2/5: authenticate server on eUICC")
    b64_auth_resp = es10b_authenticate_server_r(
      client, base64_trim(auth.get("serverSigned1", "")), base64_trim(auth.get("serverSignature1", "")),
      base64_trim(auth.get("euiccCiPKIdToBeUsed", "")), base64_trim(auth.get("serverCertificate", "")),
      matching_id=matching_id)

    log.debug("step 3/5: authenticate client with SM-DP+")
    cli = es9p_request(smdp, "authenticateClient", {"transactionId": tx_id, "authenticateServerResponse": b64_auth_resp}, "Authentication")
    metadata = es8p_metadata_parse(base64_trim(cli.get("profileMetadata", "")))
    log.debug("  profile metadata: %s", metadata)
    print(f'Downloading profile: {metadata["iccid"]} - {metadata["serviceProviderName"]} - {metadata["profileName"]}')

    log.debug("step 4/5: prepare download")
    b64_prep = es10b_prepare_download_r(
      client, base64_trim(cli.get("smdpSigned2", "")), base64_trim(cli.get("smdpSignature2", "")), base64_trim(cli.get("smdpCertificate", "")))

    log.debug("step 5/5: get and load bound profile package")
    bpp = es9p_request(smdp, "getBoundProfilePackage", {"transactionId": tx_id, "prepareDownloadResponse": b64_prep}, "GetBoundProfilePackage")

    result = es10b_load_bound_profile_package_r(client, base64_trim(bpp.get("boundProfilePackage", "")))
    if result["success"]:
      print(f"Profile installed successfully (seqNumber: {result['seqNumber']})")
    else:
      raise RuntimeError(f"Profile installation failed: {result}")
  except Exception:
    if tx_id_bytes:
      log.debug("download failed, cancelling eUICC session")
      b64_cancel_resp = ""
      try:
        b64_cancel_resp = es10b_cancel_session(client, tx_id_bytes)
      except Exception as cancel_err:
        log.debug("cancel session on eUICC failed (non-fatal): %s", cancel_err)
      try:
        es9p_request(smdp, "cancelSession", {
          "transactionId": tx_id,
          "cancelSessionResponse": b64_cancel_resp,
        }, "CancelSession")
      except Exception as cancel_err:
        log.debug("ES9+ cancelSession failed (non-fatal): %s", cancel_err)
    raise


# --- CLI ---

def build_cli() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Minimal AT-only LPA implementation")
  parser.add_argument("--device", default=DEFAULT_DEVICE)
  parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
  parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
  parser.add_argument("--verbose", action="store_true")
  parser.add_argument("--debug", action="store_true", help="Enable detailed debug logging to stderr")
  parser.add_argument("--enable", type=str)
  parser.add_argument("--disable", type=str)
  parser.add_argument("--delete", type=str, metavar="ICCID", help="Delete a disabled profile")
  parser.add_argument("--no-refresh", action="store_true", help="Skip REFRESH after enable/disable")
  parser.add_argument("--set-nickname", nargs=2, metavar=("ICCID", "NICKNAME"))
  parser.add_argument("--list-notifications", action="store_true")
  parser.add_argument("--process-notifications", action="store_true")
  parser.add_argument("--download", type=str, metavar="CODE")
  return parser


def main() -> None:
  args = build_cli().parse_args()

  logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
  )

  log.debug("parsed cli args: %s", vars(args))

  client = AtClient(args.device, args.baud, args.timeout, args.verbose)
  try:
    client.ensure_capabilities()
    client.open_isdr()
    show_profiles = True
    if args.enable:
      log.debug("action: enable profile %s", args.enable)
      enable_profile(client, args.enable, refresh=not args.no_refresh)
    elif args.disable:
      log.debug("action: disable profile %s", args.disable)
      disable_profile(client, args.disable, refresh=not args.no_refresh)
    elif args.delete:
      log.debug("action: delete profile %s", args.delete)
      delete_profile(client, args.delete)
    elif args.set_nickname:
      log.debug("action: set nickname %s -> %r", args.set_nickname[0], args.set_nickname[1])
      set_profile_nickname(client, args.set_nickname[0], args.set_nickname[1])
    elif args.list_notifications:
      log.debug("action: list notifications")
      print(json.dumps(list_notifications(client), indent=2))
      show_profiles = False
    elif args.process_notifications:
      log.debug("action: process notifications")
      process_notifications(client)
      show_profiles = False
    elif args.download:
      log.debug("action: download profile")
      download_profile(client, args.download)
    if show_profiles:
      log.debug("listing profiles")
      print(json.dumps(request_profile_info(client), indent=2))
  finally:
    client.close()


if __name__ == "__main__":
  main()
