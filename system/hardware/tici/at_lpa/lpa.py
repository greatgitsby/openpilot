import base64
import sys

from openpilot.system.hardware.base import LPABase, LPAError, LPAProfileNotFoundError, Profile
from openpilot.system.hardware.tici.at_lpa.tlv import b64e, base64_trim
from openpilot.system.hardware.tici.at_lpa.client import AtClient, DEFAULT_DEVICE, DEFAULT_BAUD, DEFAULT_TIMEOUT
from openpilot.system.hardware.tici.at_lpa.es9p import es9p_request
from openpilot.system.hardware.tici.at_lpa import es10x


def parse_lpa_activation_code(activation_code: str) -> tuple[str, str, str]:
  if not activation_code.startswith("LPA:"):
    raise ValueError("Invalid activation code format")
  parts = activation_code[4:].split("$")
  if len(parts) != 3:
    raise ValueError("Invalid activation code format")
  return parts[0], parts[1], parts[2]


def process_notifications(client: AtClient) -> None:
  notifications = es10x.list_notifications(client)
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
      notif_data = es10x.retrieve_notification(client, seq_number)
      es9p_request(smdp_address, "handleNotification", {"pendingNotification": notif_data["b64_PendingNotification"]}, "HandleNotification")
      es10x.remove_notification(client, seq_number)
      print(f"Notification {seq_number} processed successfully", file=sys.stderr)
    except Exception as e:
      print(f"Failed to process notification {seq_number}: {e}", file=sys.stderr)


def download_profile(client: AtClient, activation_code: str) -> None:
  _, smdp, matching_id = parse_lpa_activation_code(activation_code)

  challenge, euicc_info = es10x.get_challenge_and_info(client)

  payload = {"smdpAddress": smdp, "euiccChallenge": b64e(challenge), "euiccInfo1": b64e(euicc_info)}
  if matching_id:
    payload["matchingId"] = matching_id
  auth = es9p_request(smdp, "initiateAuthentication", payload, "Authentication")
  tx_id = base64_trim(auth.get("transactionId", ""))
  tx_id_bytes = base64.b64decode(tx_id) if tx_id else b""

  try:
    b64_auth_resp = es10x.authenticate_server(
      client, base64_trim(auth.get("serverSigned1", "")), base64_trim(auth.get("serverSignature1", "")),
      base64_trim(auth.get("euiccCiPKIdToBeUsed", "")), base64_trim(auth.get("serverCertificate", "")),
      matching_id=matching_id)

    cli = es9p_request(smdp, "authenticateClient", {"transactionId": tx_id, "authenticateServerResponse": b64_auth_resp}, "Authentication")
    metadata = es10x.parse_metadata(base64_trim(cli.get("profileMetadata", "")))
    print(f'Downloading profile: {metadata["iccid"]} - {metadata["serviceProviderName"]} - {metadata["profileName"]}')

    b64_prep = es10x.prepare_download(
      client, base64_trim(cli.get("smdpSigned2", "")), base64_trim(cli.get("smdpSignature2", "")), base64_trim(cli.get("smdpCertificate", "")))

    bpp = es9p_request(smdp, "getBoundProfilePackage", {"transactionId": tx_id, "prepareDownloadResponse": b64_prep}, "GetBoundProfilePackage")

    result = es10x.load_bpp(client, base64_trim(bpp.get("boundProfilePackage", "")))
    if result["success"]:
      print(f"Profile installed successfully (seqNumber: {result['seqNumber']})")
    else:
      raise RuntimeError(f"Profile installation failed: {result}")
  except Exception:
    if tx_id_bytes:
      b64_cancel_resp = ""
      try:
        b64_cancel_resp = es10x.cancel_session(client, tx_id_bytes)
      except Exception:
        pass
      try:
        es9p_request(smdp, "cancelSession", {
          "transactionId": tx_id,
          "cancelSessionResponse": b64_cancel_resp,
        }, "CancelSession")
      except Exception:
        pass
    raise


class AtLPA(LPABase):
  def __init__(self, device: str = DEFAULT_DEVICE, baud: int = DEFAULT_BAUD,
               timeout: float = DEFAULT_TIMEOUT, verbose: bool = False) -> None:
    self.device = device
    self.baud = baud
    self.timeout = timeout
    self.verbose = verbose

  def _open_client(self) -> AtClient:
    client = AtClient(self.device, self.baud, self.timeout, self.verbose)
    client.ensure_capabilities()
    client.open_isdr()
    return client

  def list_profiles(self) -> list[Profile]:
    client = self._open_client()
    try:
      raw = es10x.list_profiles(client)
      return [Profile(
        iccid=p["iccid"],
        nickname=p["profileNickname"] or "",
        enabled=p["profileState"] == "enabled",
        provider=p["serviceProviderName"] or "",
      ) for p in raw]
    finally:
      client.close()

  def get_active_profile(self) -> Profile | None:
    return next((p for p in self.list_profiles() if p.enabled), None)

  def delete_profile(self, iccid: str) -> None:
    self._validate_profile_exists(iccid)
    active = self.get_active_profile()
    if active is not None and active.iccid == iccid:
      raise LPAError("cannot delete active profile, switch to another profile first")
    client = self._open_client()
    try:
      es10x.delete_profile(client, iccid)
    finally:
      client.close()
    self.process_notifications()

  def download_profile(self, qr: str, nickname: str | None = None) -> None:
    client = self._open_client()
    try:
      download_profile(client, qr)
      profiles = es10x.list_profiles(client)
    finally:
      client.close()
    if nickname:
      new_iccid = next((p["iccid"] for p in profiles if p["profileNickname"] == "" or p["profileNickname"] is None), None)
      if new_iccid:
        self.nickname_profile(new_iccid, nickname)
    self.process_notifications()

  def nickname_profile(self, iccid: str, nickname: str) -> None:
    self._validate_profile_exists(iccid)
    client = self._open_client()
    try:
      es10x.set_profile_nickname(client, iccid, nickname)
    finally:
      client.close()

  def switch_profile(self, iccid: str) -> None:
    self._validate_profile_exists(iccid)
    active = self.get_active_profile()
    if active and active.iccid == iccid:
      return
    client = self._open_client()
    try:
      if active:
        es10x.disable_profile(client, active.iccid)
      es10x.enable_profile(client, iccid)
    finally:
      client.close()
    self.process_notifications()

  def enable_profile(self, iccid: str) -> None:
    self._validate_profile_exists(iccid)
    client = self._open_client()
    try:
      es10x.enable_profile(client, iccid)
    finally:
      client.close()
    self.process_notifications()

  def disable_profile(self, iccid: str) -> None:
    self._validate_profile_exists(iccid)
    client = self._open_client()
    try:
      es10x.disable_profile(client, iccid)
    finally:
      client.close()
    self.process_notifications()

  def process_notifications(self) -> None:
    client = self._open_client()
    try:
      process_notifications(client)
    finally:
      client.close()

  def _validate_profile_exists(self, iccid: str) -> None:
    if not any(p.iccid == iccid for p in self.list_profiles()):
      raise LPAProfileNotFoundError(f"profile {iccid} does not exist")
