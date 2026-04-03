# SGP.22 v2.3: https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2021/07/SGP.22-v2.3.pdf

import atexit
import base64
import hashlib
import math
import os
import requests
import serial
import subprocess
import sys
import time

from collections.abc import Callable, Generator
from typing import Any
from pathlib import Path

from openpilot.common.time_helpers import system_time_valid
from openpilot.common.utils import retry
from openpilot.system.hardware.base import LPABase, LPAError, Profile

GSMA_CI_BUNDLE = str(Path(__file__).parent / 'gsma_ci_bundle.pem')


DEFAULT_DEVICE = "/dev/modem_at0"
DEFAULT_BAUD = 9600
DEFAULT_TIMEOUT = 5.0
# https://euicc-manual.osmocom.org/docs/lpa/applet-id/
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
MM = "org.freedesktop.ModemManager1"
MM_MODEM = MM + ".Modem"
ES10X_MSS = 120
DEBUG = True

# TLV Tags
TAG_ICCID = 0x5A
TAG_STATUS = 0x80
TAG_PROFILE_INFO_LIST = 0xBF2D
TAG_LIST_NOTIFICATION = 0xBF28
TAG_RETRIEVE_NOTIFICATION = 0xBF2B
TAG_NOTIFICATION_METADATA = 0xBF2F
TAG_NOTIFICATION_SENT = 0xBF30
TAG_ENABLE_PROFILE = 0xBF31
TAG_DELETE_PROFILE = 0xBF33
TAG_EUICC_INFO = 0xBF20
TAG_PREPARE_DOWNLOAD = 0xBF21
TAG_EUICC_CHALLENGE = 0xBF2E
TAG_SET_NICKNAME = 0xBF29
TAG_PROFILE_INSTALL_RESULT = 0xBF37
TAG_BPP = 0xBF36
TAG_AUTH_SERVER = 0xBF38
TAG_CANCEL_SESSION = 0xBF41
TAG_OK = 0xA0

CAT_BUSY = 0x05

PROFILE_ERROR_CODES = {
  0x01: "iccidOrAidNotFound", 0x02: "profileNotInDisabledState",
  0x03: "disallowedByPolicy", 0x04: "wrongProfileReenabling",
  CAT_BUSY: "catBusy", 0x06: "undefinedError",
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
BPP_ERROR_MESSAGES = {
  9: "This eSIM profile is already installed on this device.",
  10: "Not enough memory on the eUICC to install this profile.",
  12: "Profile installation failed. The QR code may have already been used.",
}

# SGP.22 §5.2.6 — SM-DP+ reason/subject codes mapped to user-friendly messages
# https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2021/07/SGP.22-v2.3.pdf
ES9P_ERROR_MESSAGES: dict[tuple[str, str], str] = {
  ('3.8', '8.2.6'): "This eSIM profile is already installed on another device. Please use a new QR code.",
  ('3.8', '8.2.1'): "This eSIM profile has expired. Please request a new QR code.",
  ('3.8', '8.1'): "The SM-DP+ server refused this request.",
  ('3.1', '8.2.6'): "This eSIM profile has been revoked by the carrier.",
  ('3.9', '8.2.6'): "This eSIM profile download has already been completed.",
  ('2.1', '8.8'): "The device is not compatible with this eSIM profile.",
  ('1.2', '8.1'): "The SM-DP+ server is temporarily unavailable. Try again later.",
}

STATE_LABELS = {0: "disabled", 1: "enabled", 255: "unknown"}
ICON_LABELS = {0: "jpeg", 1: "png", 255: "unknown"}
CLASS_LABELS = {0: "test", 1: "provisioning", 2: "operational", 255: "unknown"}

# TLV tag -> (field_name, decoder)
FieldMap = dict[int, tuple[str, Callable[[bytes], Any]]]


def b64e(data: bytes) -> str:
  return base64.b64encode(data).decode("ascii")


def base64_trim(s: str) -> str:
  return "".join(c for c in s if c not in "\n\r \t")


def b64d(s: str) -> bytes:
  return base64.b64decode(base64_trim(s))


class AtClient:
  def __init__(self, device: str, baud: int, timeout: float, debug: bool) -> None:
    self.debug = debug
    self.channel: str | None = None
    self._device = device
    self._baud = baud
    self._timeout = timeout
    self._serial: serial.Serial | None = None
    try:
      self._serial = serial.Serial(device, baudrate=baud, timeout=timeout)
      self._disable_echo()
    except (serial.SerialException, PermissionError, OSError):
      pass

  def close(self) -> None:
    try:
      if self.channel:
        try:
          self.query(f"AT+CCHC={self.channel}")
        except (RuntimeError, TimeoutError):
          pass
        self.channel = None
    finally:
      if self._serial:
        self._serial.close()

  def _disable_echo(self) -> None:
    """Disable command echo and drain any stale data from the serial buffer."""
    self._serial.reset_input_buffer()
    self._serial.write(b"ATE0\r")
    time.sleep(0.1)
    self._serial.reset_input_buffer()

  def _send(self, cmd: str) -> None:
    if self.debug:
      print(f"SER >> {cmd}", file=sys.stderr)
    self._serial.write((cmd + "\r").encode("ascii"))

  def _expect(self) -> list[str]:
    lines: list[str] = []
    while True:
      raw = self._serial.readline()
      if not raw:
        raise TimeoutError("AT command timed out")
      line = raw.decode(errors="ignore").strip()
      if not line:
        continue
      if self.debug:
        print(f"SER << {line}", file=sys.stderr)
      if line == "OK":
        return lines
      if line == "ERROR" or line.startswith("+CME ERROR"):
        raise RuntimeError(f"AT command failed: {line}")
      lines.append(line)

  def _get_modem(self):
    import dbus
    bus = dbus.SystemBus()
    mm = bus.get_object(MM, '/org/freedesktop/ModemManager1')
    objects = mm.GetManagedObjects(dbus_interface="org.freedesktop.DBus.ObjectManager", timeout=self._timeout)
    modem_path = list(objects.keys())[0]
    return bus.get_object(MM, modem_path)

  def _dbus_query(self, cmd: str) -> list[str]:
    if self.debug:
      print(f"DBUS >> {cmd}", file=sys.stderr)
    try:
      result = str(self._get_modem().Command(cmd, math.ceil(self._timeout), dbus_interface=MM_MODEM, timeout=self._timeout))
    except Exception as e:
      raise RuntimeError(f"AT command failed: {e}") from e
    lines = [line.strip() for line in result.splitlines() if line.strip()]
    if self.debug:
      for line in lines:
        print(f"DBUS << {line}", file=sys.stderr)
    return lines

  def _reconnect_serial(self) -> None:
    """Reopen the serial port after it goes stale (e.g. modem reboot)."""
    self.channel = None
    try:
      if self._serial:
        self._serial.close()
    except Exception:
      pass
    self._serial = serial.Serial(self._device, baudrate=self._baud, timeout=self._timeout)
    self._disable_echo()

  def query(self, cmd: str) -> list[str]:
    if self._serial:
      try:
        self._send(cmd)
        return self._expect()
      except serial.SerialException:
        self._reconnect_serial()
        self._send(cmd)
        return self._expect()
    return self._dbus_query(cmd)

  def _open_isdr_once(self) -> None:
    """Try once to open ISD-R. Raises on failure."""
    if self.channel:
      try:
        self.query(f"AT+CCHC={self.channel}")
      except RuntimeError:
        pass
      self.channel = None
    # drain any unsolicited responses before opening
    if self._serial:
      try:
        self._serial.reset_input_buffer()
      except (OSError, serial.SerialException):
        self._reconnect_serial()
    for line in self.query(f'AT+CCHO="{ISDR_AID}"'):
      if line.startswith("+CCHO:") and (ch := line.split(":", 1)[1].strip()):
        self.channel = ch
        return
    raise RuntimeError("Failed to open ISD-R application")

  def open_isdr(self) -> None:
    for attempt in range(10):
      try:
        self._open_isdr_once()
        return
      except (RuntimeError, TimeoutError) as e:
        if self.debug:
          print(f"open_isdr failed, trying again", file=sys.stderr)
        if attempt == 3:
          # SIM may be stuck (CME ERROR 13) — reset modem via lte.sh
          subprocess.run(['/usr/comma/lte/lte.sh', 'start'], capture_output=True)
          time.sleep(5)
          self._reconnect_serial()
        else:
          time.sleep(2.0)
    raise RuntimeError("Failed to open ISD-R after retries")

  def send_apdu(self, apdu: bytes, max_retries: int = 3) -> tuple[bytes, int, int]:
    for attempt in range(max_retries):
      try:
        if not self.channel:
          self.open_isdr()
        hex_payload = apdu.hex().upper()
        for line in self.query(f'AT+CGLA={self.channel},{len(hex_payload)},"{hex_payload}"'):
          if line.startswith("+CGLA:"):
            parts = line.split(":", 1)[1].split(",", 1)
            if len(parts) == 2:
              data = bytes.fromhex(parts[1].strip().strip('"'))
              if len(data) >= 2:
                return data[:-2], data[-2], data[-1]
        raise RuntimeError("Missing +CGLA response")
      except (RuntimeError, ValueError):
        self.channel = None
        if attempt == max_retries - 1:
          raise
        time.sleep(1 + attempt)
    raise RuntimeError("send_apdu failed")


# --- TLV utilities ---

def iter_tlv(data: bytes, with_positions: bool = False) -> Generator:
  idx, length = 0, len(data)
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
    yield (tag_value, value, start_pos, idx) if with_positions else (tag_value, value)


def find_tag(data: bytes, target: int) -> bytes | None:
  return next((v for t, v in iter_tlv(data) if t == target), None)


def require_tag(data: bytes, target: int, label: str = "") -> bytes:
  v = find_tag(data, target)
  if v is None:
    raise RuntimeError(f"Missing {label or f'tag 0x{target:X}'}")
  return v


def tbcd_to_string(raw: bytes) -> str:
  return "".join(str(n) for b in raw for n in (b & 0x0F, b >> 4) if n <= 9)


def string_to_tbcd(s: str) -> bytes:
  digits = [int(c) for c in s if c.isdigit()]
  return bytes(digits[i] | ((digits[i + 1] if i + 1 < len(digits) else 0xF) << 4) for i in range(0, len(digits), 2))


def encode_tlv(tag: int, value: bytes) -> bytes:
  tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF]) if tag > 255 else bytes([tag])
  vlen = len(value)
  if vlen <= 127:
    return tag_bytes + bytes([vlen]) + value
  length_bytes = vlen.to_bytes((vlen.bit_length() + 7) // 8, "big")
  return tag_bytes + bytes([0x80 | len(length_bytes)]) + length_bytes + value


def int_bytes(n: int) -> bytes:
  """Encode a positive integer as minimal big-endian bytes (at least 1 byte)."""
  return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")


PROFILE: FieldMap = {
  TAG_ICCID: ("iccid", tbcd_to_string),
  0x4F: ("isdpAid", lambda v: v.hex().upper()),
  0x9F70: ("profileState", lambda v: STATE_LABELS.get(v[0], "unknown")),
  0x90: ("profileNickname", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x91: ("serviceProviderName", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x92: ("profileName", lambda v: v.decode("utf-8", errors="ignore") or None),
  0x93: ("iconType", lambda v: ICON_LABELS.get(v[0], "unknown")),
  0x94: ("icon", b64e),
  0x95: ("profileClass", lambda v: CLASS_LABELS.get(v[0], "unknown")),
}

NOTIFICATION: FieldMap = {
  TAG_STATUS: ("seqNumber", lambda v: int.from_bytes(v, "big")),
  0x81: ("profileManagementOperation", lambda v: next((m for m in [0x80, 0x40, 0x20, 0x10] if len(v) >= 2 and v[1] & m), 0xFF)),
  0x0C: ("notificationAddress", lambda v: v.decode("utf-8", errors="ignore")),
  TAG_ICCID: ("iccid", tbcd_to_string),
}


def decode_struct(data: bytes, field_map: FieldMap) -> dict[str, Any]:
  """Parse TLV data using a {tag: (field_name, decoder)} map into a dict."""
  result: dict[str, Any] = {name: None for name, _ in field_map.values()}
  for tag, value in iter_tlv(data):
    if (field := field_map.get(tag)):
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
    is_last = offset == len(data)
    apdu = bytes([0x80, 0xE2, 0x91 if is_last else 0x11, sequence & 0xFF, len(chunk)]) + chunk
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


# --- Profile operations ---

def decode_profiles(blob: bytes) -> list[dict]:
  root = require_tag(blob, TAG_PROFILE_INFO_LIST, "ProfileInfoList")
  list_ok = find_tag(root, TAG_OK)
  if list_ok is None:
    return []
  return [decode_struct(value, PROFILE) for tag, value in iter_tlv(list_ok) if tag == 0xE3]


def list_profiles(client: AtClient) -> list[dict]:
  return decode_profiles(es10x_command(client, TAG_PROFILE_INFO_LIST.to_bytes(2, "big") + b"\x00"))


# --- ES9P HTTP ---

def es9p_request(smdp_address: str, endpoint: str, payload: dict, error_prefix: str = "Request") -> dict:
  if not system_time_valid():
    raise RuntimeError("System time is not set; TLS certificate validation requires a valid clock")
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/{endpoint}"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.3.0", "Content-Type": "application/json"}
  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=GSMA_CI_BUNDLE)
  resp.raise_for_status()
  if not resp.content:
    return {}
  data = resp.json()
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      sd = status.get("statusCodeData", {})
      reason = sd.get('reasonCode', 'unknown')
      subject = sd.get('subjectCode', 'unknown')
      msg = ES9P_ERROR_MESSAGES.get((reason, subject),
            f"{error_prefix} failed: {reason}/{subject} - {sd.get('message', 'unknown')}")
      raise RuntimeError(msg)
  return data


# --- Notifications ---

def list_notifications(client: AtClient) -> list[dict]:
  response = es10x_command(client, encode_tlv(TAG_LIST_NOTIFICATION, b""))
  root = require_tag(response, TAG_LIST_NOTIFICATION, "ListNotificationResponse")
  metadata_list = find_tag(root, TAG_OK)
  if metadata_list is None:
    return []
  notifications: list[dict] = []
  for tag, value in iter_tlv(metadata_list):
    if tag != TAG_NOTIFICATION_METADATA:
      continue
    notification = decode_struct(value, NOTIFICATION)
    if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"]:
      notifications.append(notification)
  return notifications


def process_notifications(client: AtClient) -> None:
  for notification in list_notifications(client):
    seq_number, smdp_address = notification["seqNumber"], notification["notificationAddress"]
    try:
      # retrieve notification
      request = encode_tlv(TAG_RETRIEVE_NOTIFICATION, encode_tlv(TAG_OK, encode_tlv(TAG_STATUS, int_bytes(seq_number))))
      response = es10x_command(client, request)
      content = require_tag(require_tag(response, TAG_RETRIEVE_NOTIFICATION, "RetrieveNotificationsListResponse"),
                            TAG_OK, "RetrieveNotificationsListResponse")
      pending_notif = next((v for t, v in iter_tlv(content) if t in (TAG_PROFILE_INSTALL_RESULT, 0x30)), None)
      if pending_notif is None:
        raise RuntimeError("Missing PendingNotification")

      # send to SM-DP+
      es9p_request(smdp_address, "handleNotification", {"pendingNotification": b64e(pending_notif)}, "HandleNotification")

      # remove notification
      response = es10x_command(client, encode_tlv(TAG_NOTIFICATION_SENT, encode_tlv(TAG_STATUS, int_bytes(seq_number))))
      root = require_tag(response, TAG_NOTIFICATION_SENT, "NotificationSentResponse")
      if int.from_bytes(require_tag(root, TAG_STATUS, "RemoveNotificationFromList status"), "big") != 0:
        raise RuntimeError("RemoveNotificationFromList failed")
    except Exception:
      pass



# --- Authentication & Download ---

def get_challenge_and_info(client: AtClient) -> tuple[bytes, bytes]:
  challenge_resp = es10x_command(client, encode_tlv(TAG_EUICC_CHALLENGE, b""))
  challenge = require_tag(require_tag(challenge_resp, TAG_EUICC_CHALLENGE, "GetEuiccDataResponse"),
                          TAG_STATUS, "challenge in response")
  info_resp = es10x_command(client, encode_tlv(TAG_EUICC_INFO, b""))
  if not info_resp.startswith(bytes([0xBF, 0x20])):
    raise RuntimeError("Missing GetEuiccInfo1Response")
  return challenge, info_resp


def authenticate_server(client: AtClient, b64_signed1: str, b64_sig1: str, b64_pk_id: str, b64_cert: str, matching_id: str | None = None) -> str:
  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = encode_tlv(TAG_STATUS, tac) + encode_tlv(0xA1, b"")
  ctx_inner = b""
  if matching_id:
    ctx_inner += encode_tlv(TAG_STATUS, matching_id.encode("utf-8"))
  ctx_inner += encode_tlv(0xA1, device_info)
  content = base64.b64decode(b64_signed1) + base64.b64decode(b64_sig1) + base64.b64decode(b64_pk_id) + base64.b64decode(b64_cert) + encode_tlv(0xA0, ctx_inner)
  response = es10x_command(client, encode_tlv(TAG_AUTH_SERVER, content))
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse")
  root = find_tag(response, TAG_AUTH_SERVER)
  if root is not None:
    error_tag = find_tag(root, 0xA1)
    if error_tag is not None:
      code = int.from_bytes(error_tag, "big") if error_tag else 0
      raise RuntimeError(f"AuthenticateServer rejected by eUICC: {AUTH_SERVER_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})")
  return b64e(response)


def prepare_download(client: AtClient, b64_signed2: str, b64_sig2: str, b64_cert: str, cc: str | None = None) -> str:
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
  return b64e(response)


def _parse_tlv_header_len(data: bytes) -> int:
  tag_len = 2 if data[0] & 0x1F == 0x1F else 1
  length_byte = data[tag_len]
  return tag_len + (1 + (length_byte & 0x7F) if length_byte & 0x80 else 1)


def load_bpp(client: AtClient, b64_bpp: str) -> dict:
  bpp = b64d(b64_bpp)
  if not bpp.startswith(bytes([0xBF, 0x36])):
    raise RuntimeError("Invalid BoundProfilePackage")

  bpp_root_value = None
  for tag, value, start, end in iter_tlv(bpp, with_positions=True):
    if tag == TAG_BPP:
      bpp_root_value = value
      bpp_value_start = start + _parse_tlv_header_len(bpp[start:end])
      break
  if bpp_root_value is None:
    raise RuntimeError("Invalid BoundProfilePackage")

  chunks: list[bytes] = []
  for tag, value, start, end in iter_tlv(bpp_root_value, with_positions=True):
    if tag == 0xBF23:
      chunks.append(bpp[0 : bpp_value_start + end])
    elif tag == 0xA0:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])
    elif tag in (0xA1, 0xA3):
      hdr_len = _parse_tlv_header_len(bpp_root_value[start:end])
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + start + hdr_len])
      for _, _, child_start, child_end in iter_tlv(value, with_positions=True):
        chunks.append(value[child_start:child_end])
    elif tag == 0xA2:
      chunks.append(bpp[bpp_value_start + start : bpp_value_start + end])

  result: dict[str, Any] = {"seqNumber": 0, "success": False, "bppCommandId": None, "errorReason": None}
  for chunk in chunks:
    response = es10x_command(client, chunk)
    if not response:
      continue
    root = find_tag(response, TAG_PROFILE_INSTALL_RESULT)
    if not root:
      continue
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
    break
  if not result["success"] and result["errorReason"] is not None:
    msg = BPP_ERROR_MESSAGES.get(result["errorReason"])
    if not msg:
      cmd_name = BPP_COMMAND_NAMES.get(result["bppCommandId"], f"unknown({result['bppCommandId']})")
      err_name = BPP_ERROR_REASONS.get(result["errorReason"], f"unknown({result['errorReason']})")
      msg = f"Profile installation failed at {cmd_name}: {err_name}"
    raise RuntimeError(msg)
  return result


def parse_metadata(b64_metadata: str) -> dict:
  root = find_tag(b64d(b64_metadata), 0xBF25)
  if root is None:
    raise RuntimeError("Invalid profileMetadata")
  return decode_struct(root, PROFILE)


def cancel_session(client: AtClient, transaction_id: bytes, reason: int = 127) -> str:
  content = encode_tlv(0x80, transaction_id) + encode_tlv(0x81, bytes([reason]))
  response = es10x_command(client, encode_tlv(TAG_CANCEL_SESSION, content))
  return b64e(response)


def parse_lpa_activation_code(activation_code: str) -> tuple[str, str, str]:
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def download_profile(client: AtClient, activation_code: str) -> str:
  """Download and install an eSIM profile. Returns the ICCID of the installed profile."""
  _, smdp, matching_id = parse_lpa_activation_code(activation_code)

  challenge, euicc_info = get_challenge_and_info(client)

  payload: dict[str, str] = {"smdpAddress": smdp, "euiccChallenge": b64e(challenge), "euiccInfo1": b64e(euicc_info)}
  if matching_id:
    payload["matchingId"] = matching_id
  auth = es9p_request(smdp, "initiateAuthentication", payload, "Authentication")
  tx_id = base64_trim(auth.get("transactionId", ""))
  tx_id_bytes = base64.b64decode(tx_id) if tx_id else b""

  try:
    b64_auth_resp = authenticate_server(
      client, base64_trim(auth.get("serverSigned1", "")), base64_trim(auth.get("serverSignature1", "")),
      base64_trim(auth.get("euiccCiPKIdToBeUsed", "")), base64_trim(auth.get("serverCertificate", "")),
      matching_id=matching_id)

    cli = es9p_request(smdp, "authenticateClient", {"transactionId": tx_id, "authenticateServerResponse": b64_auth_resp}, "Authentication")
    metadata = parse_metadata(base64_trim(cli.get("profileMetadata", "")))
    iccid = metadata.get("iccid", "")

    b64_prep = prepare_download(
      client, base64_trim(cli.get("smdpSigned2", "")), base64_trim(cli.get("smdpSignature2", "")), base64_trim(cli.get("smdpCertificate", "")))

    bpp = es9p_request(smdp, "getBoundProfilePackage", {"transactionId": tx_id, "prepareDownloadResponse": b64_prep}, "GetBoundProfilePackage")

    result = load_bpp(client, base64_trim(bpp.get("boundProfilePackage", "")))
    if not result["success"]:
      raise RuntimeError(f"Profile installation failed: {result}")
    return iccid
  except Exception:
    if tx_id_bytes:
      b64_cancel_resp = ""
      try:
        b64_cancel_resp = cancel_session(client, tx_id_bytes)
      except Exception:
        pass
      try:
        es9p_request(smdp, "cancelSession", {"transactionId": tx_id, "cancelSessionResponse": b64_cancel_resp}, "CancelSession")
      except Exception:
        pass
    raise


def set_profile_nickname(client: AtClient, iccid: str, nickname: str) -> None:
  nickname_bytes = nickname.encode("utf-8")
  if len(nickname_bytes) > 64:
    raise ValueError("Profile nickname must be 64 bytes or less")
  content = encode_tlv(TAG_ICCID, string_to_tbcd(iccid)) + encode_tlv(0x90, nickname_bytes)
  response = es10x_command(client, encode_tlv(TAG_SET_NICKNAME, content))
  root = require_tag(response, TAG_SET_NICKNAME, "SetNicknameResponse")
  code = require_tag(root, TAG_STATUS, "status in SetNicknameResponse")[0]
  if code == 0x01:
    raise LPAError(f"profile {iccid} not found")
  if code != 0x00:
    raise RuntimeError(f"SetNickname failed with status 0x{code:02X}")


class TiciLPA(LPABase):
  _instance = None

  def __new__(cls):
    if cls._instance is None:
      cls._instance = super().__new__(cls)
    return cls._instance

  def __init__(self):
    if hasattr(self, '_client'):
      return
    self._client = AtClient(DEFAULT_DEVICE, DEFAULT_BAUD, DEFAULT_TIMEOUT, debug=DEBUG)
    self._client.open_isdr()
    atexit.register(self._client.close)



  def list_profiles(self) -> list[Profile]:
    profiles = list_profiles(self._client)
    return [
      Profile(
        iccid=p.get("iccid", ""),
        nickname=p.get("profileNickname") or "",
        enabled=p.get("profileState") == "enabled",
        provider=p.get("serviceProviderName") or "",
      )
      for p in profiles
    ]

  def get_active_profile(self) -> Profile | None:
    return None

  def process_notifications(self) -> None:
    process_notifications(self._client)

  def _prepare_for_profile_switch(self) -> None:
    """SGP.22 §3.2.1 step 1: terminate active sessions before EnableProfile/DeleteProfile."""
    # Close our logical channel to end the application session
    if self._client.channel:
      try:
        self._client.query(f"AT+CCHC={self._client.channel}")
      except (RuntimeError, TimeoutError):
        pass
      self._client.channel = None
    time.sleep(0.5)

  def _delete_profile(self, iccid: str) -> int:
    request = encode_tlv(TAG_DELETE_PROFILE, encode_tlv(TAG_ICCID, string_to_tbcd(iccid)))
    response = es10x_command(self._client, request)
    root = require_tag(response, TAG_DELETE_PROFILE, "DeleteProfileResponse")
    return require_tag(root, TAG_STATUS, "status in DeleteProfileResponse")[0]

  def delete_profile(self, iccid: str) -> None:
    if self.is_comma_profile(iccid):
      raise LPAError("refusing to delete a comma profile")
    self._prepare_for_profile_switch()
    for attempt in range(4):
      code = self._delete_profile(iccid)
      if code != CAT_BUSY:
        break
      self._prepare_for_profile_switch()
    if code != 0x00:
      raise LPAError(f"DeleteProfile failed: {PROFILE_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})")

  def download_profile(self, qr: str, nickname: str | None = None) -> None:
    iccid = download_profile(self._client, qr)
    if nickname and iccid:
      self.nickname_profile(iccid, nickname)

  def nickname_profile(self, iccid: str, nickname: str) -> None:
    set_profile_nickname(self._client, iccid, nickname)

  def _enable_profile(self, iccid: str, refresh: bool = True) -> int:
    inner = encode_tlv(TAG_OK, encode_tlv(TAG_ICCID, string_to_tbcd(iccid)))
    inner += b'\x01\x01' + (b'\xFF' if refresh else b'\x00')  # refreshFlag BOOLEAN
    request = encode_tlv(TAG_ENABLE_PROFILE, inner)
    response = es10x_command(self._client, request)
    root = require_tag(response, TAG_ENABLE_PROFILE, "EnableProfileResponse")
    return require_tag(root, TAG_STATUS, "status in EnableProfileResponse")[0]

  def reset_modem(self) -> None:
    """CFUN cycle + ModemManager restart to force re-read of eUICC after profile switch."""
    self._client.channel = None
    try:
      self._client.query('AT+CFUN=0')
    except Exception:
      pass
    time.sleep(2)
    try:
      self._client.query('AT+CFUN=1')
    except Exception:
      pass
    time.sleep(3)
    subprocess.run(['sudo', 'systemctl', 'restart', 'ModemManager'], capture_output=True)

  def switch_profile(self, iccid: str) -> None:
    # refresh=False avoids catBusy from active proactive sessions.
    # modem re-reads the eUICC via CFUN cycle or REFRESH handled externally.
    self._prepare_for_profile_switch()
    for attempt in range(4):
      code = self._enable_profile(iccid, refresh=False)
      if code != CAT_BUSY:
        break
      self._prepare_for_profile_switch()
    if code not in (0x00, 0x02):  # 0x02 = already enabled
      raise LPAError(f"EnableProfile failed: {PROFILE_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})")
    if code == 0x00:
      self._client.channel = None
