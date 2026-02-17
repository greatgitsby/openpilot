import base64
import hashlib

from openpilot.system.hardware.tici.at_lpa.tlv import (
  b64d, b64e, base64_trim, encode_tlv, find_tag, int_bytes, iter_tlv,
  string_to_tbcd, tbcd_to_string,
)
from openpilot.system.hardware.tici.at_lpa.client import AtClient, es10x_command


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


def _decode_profile_fields(data: bytes) -> dict:
  """Parse known profile metadata TLV fields into a dict."""
  result = {}
  for tag, value in iter_tlv(data):
    if (field := _PROFILE_FIELDS.get(tag)):
      result[field[0]] = field[1](value)
  return result


# Notification field decoders: TLV tag -> (field_name, decoder)
_NOTIF_FIELDS = {
  TAG_STATUS: ("seqNumber", lambda v: int.from_bytes(v, "big")),
  0x81: ("profileManagementOperation", lambda v: next((m for m in [0x80, 0x40, 0x20, 0x10] if len(v) >= 2 and v[1] & m), 0xFF)),
  0x0C: ("notificationAddress", lambda v: v.decode("utf-8", errors="ignore")),
  TAG_ICCID: ("iccid", tbcd_to_string),
}


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


def list_profiles(client: AtClient) -> list[dict]:
  return decode_profiles(es10x_command(client, bytes.fromhex("BF2D00")))


def _profile_op(client: AtClient, tag: int, iccid: str, refresh: bool, action: str) -> None:
  if tag == TAG_DELETE_PROFILE:
    inner = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
  else:
    inner = encode_tlv(TAG_ICCID, string_to_tbcd(iccid))
    if not refresh:
      inner += encode_tlv(0x81, b'\x00')
    inner = encode_tlv(0xA0, inner)
  code = _extract_status(es10x_command(client, encode_tlv(tag, inner)), tag, f"{action.capitalize()}Profile")
  if code == 0x00:
    return
  if code == 0x02 and tag != TAG_DELETE_PROFILE:
    print(f"profile {iccid} already {action}d")
    return
  raise RuntimeError(f"{action.capitalize()}Profile failed: {PROFILE_ERROR_CODES.get(code, 'unknown')} (0x{code:02X})")


def enable_profile(client: AtClient, iccid: str, refresh: bool = True) -> None:
  _profile_op(client, TAG_ENABLE_PROFILE, iccid, refresh, "enable")


def disable_profile(client: AtClient, iccid: str, refresh: bool = True) -> None:
  _profile_op(client, TAG_DISABLE_PROFILE, iccid, refresh, "disable")


def delete_profile(client: AtClient, iccid: str) -> None:
  _profile_op(client, TAG_DELETE_PROFILE, iccid, True, "delete")


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
      if (field := _NOTIF_FIELDS.get(t)):
        notification[field[0]] = field[1](v)
    if notification["seqNumber"] is not None and notification["profileManagementOperation"] is not None and notification["notificationAddress"]:
      notifications.append(notification)
  return notifications


def retrieve_notification(client: AtClient, seq_number: int) -> dict:
  request = encode_tlv(TAG_RETRIEVE_NOTIFICATION, encode_tlv(0xA0, encode_tlv(TAG_STATUS, int_bytes(seq_number))))
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
  return {"notificationAddress": addr.decode("utf-8", errors="ignore"), "b64_PendingNotification": b64e(pending_notif)}


def remove_notification(client: AtClient, seq_number: int) -> None:
  response = es10x_command(client, encode_tlv(TAG_NOTIFICATION_SENT, encode_tlv(TAG_STATUS, int_bytes(seq_number))))
  root = find_tag(response, TAG_NOTIFICATION_SENT)
  if root is None:
    raise RuntimeError("Invalid NotificationSentResponse")
  status = find_tag(root, TAG_STATUS)
  if status is None or int.from_bytes(status, "big") != 0:
    raise RuntimeError("RemoveNotificationFromList failed")


# --- Authentication & Download ---

def get_challenge_and_info(client: AtClient) -> tuple[bytes, bytes]:
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


def authenticate_server(client: AtClient, b64_signed1: str, b64_sig1: str, b64_pk_id: str, b64_cert: str, matching_id: str | None = None) -> str:
  # Build request
  tac = bytes([0x35, 0x29, 0x06, 0x11])
  device_info = encode_tlv(TAG_STATUS, tac) + encode_tlv(0xA1, b"")
  ctx_inner = b""
  if matching_id:
    ctx_inner += encode_tlv(TAG_STATUS, matching_id.encode("utf-8"))
  ctx_inner += encode_tlv(0xA1, device_info)
  content = base64.b64decode(b64_signed1) + base64.b64decode(b64_sig1) + base64.b64decode(b64_pk_id) + base64.b64decode(b64_cert) + encode_tlv(0xA0, ctx_inner)
  request = encode_tlv(TAG_AUTH_SERVER, content)

  response = es10x_command(client, request)
  if not response.startswith(bytes([0xBF, 0x38])):
    raise RuntimeError("Invalid AuthenticateServerResponse")

  # Check for eUICC-side errors
  root = find_tag(response, TAG_AUTH_SERVER)
  if root is not None:
    error_tag = find_tag(root, 0xA1)
    if error_tag is not None:
      code = int.from_bytes(error_tag, "big") if error_tag else 0
      desc = AUTH_SERVER_ERROR_CODES.get(code, "unknown")
      raise RuntimeError(f"AuthenticateServer rejected by eUICC: {desc} (0x{code:02X})")

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
  """Return the combined tag + length header size for a TLV element."""
  tag_len = 2 if data[0] & 0x1F == 0x1F else 1
  length_byte = data[tag_len]
  return tag_len + (1 + (length_byte & 0x7F) if length_byte & 0x80 else 1)


def load_bpp(client: AtClient, b64_bpp: str) -> dict:
  bpp = b64d(b64_bpp)
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
  if not result["success"] and result["errorReason"] is not None:
    cmd_name = BPP_COMMAND_NAMES.get(result["bppCommandId"], f"unknown({result['bppCommandId']})")
    err_name = BPP_ERROR_REASONS.get(result["errorReason"], f"unknown({result['errorReason']})")
    raise RuntimeError(f"Profile installation failed at {cmd_name}: {err_name} (bppCommandId={result['bppCommandId']}, errorReason={result['errorReason']})")
  return result


def parse_metadata(b64_metadata: str) -> dict:
  root = find_tag(b64d(b64_metadata), 0xBF25)
  if root is None:
    raise RuntimeError("Invalid profileMetadata")
  defaults = {"iccid": None, "serviceProviderName": None, "profileName": None, "iconType": None, "icon": None, "profileClass": None}
  return {**defaults, **_decode_profile_fields(root)}


def cancel_session(client: AtClient, transaction_id: bytes, reason: int = 127) -> str:
  content = encode_tlv(0x80, transaction_id) + encode_tlv(0x81, bytes([reason]))
  response = es10x_command(client, encode_tlv(TAG_CANCEL_SESSION, content))
  return b64e(response)
