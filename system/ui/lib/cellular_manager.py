import subprocess
import time
import threading
from collections.abc import Callable

from openpilot.common.swaglog import cloudlog
from openpilot.system.hardware.base import LPABase, Profile

MODEM_IP_POLL_INTERVAL = 5.0
DOWNLOAD_TIMEOUT = 120  # seconds


def _get_modem_ip() -> str:
  for iface in ("ppp0", "wwan0"):
    try:
      out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", iface], timeout=1, text=True, stderr=subprocess.DEVNULL)
      parts = out.split()
      for i, part in enumerate(parts):
        if part == "inet" and i + 1 < len(parts):
          return parts[i + 1].split("/")[0]
    except Exception:
      pass
  return ""


LPA_RETRY_INTERVAL = 5.0


def _get_lpa() -> LPABase:
  from openpilot.system.hardware import HARDWARE
  return HARDWARE.get_sim_lpa()


class CellularManager:
  def __init__(self):
    self._lpa: LPABase | None = None
    self._profiles: list[Profile] = []
    self._busy: bool = False
    self._switching_iccid: str | None = None

    self._lock = threading.Lock()
    self._callback_queue: list[Callable] = []

    self._profiles_updated_cbs: list[Callable[[list[Profile]], None]] = []
    self._operation_error_cbs: list[Callable[[str], None]] = []

    self._modem_ip: str = _get_modem_ip()
    self._last_ip_poll: float = 0.0

  def add_callbacks(self, profiles_updated: Callable | None = None, operation_error: Callable | None = None):
    if profiles_updated:
      self._profiles_updated_cbs.append(profiles_updated)
    if operation_error:
      self._operation_error_cbs.append(operation_error)

  @property
  def modem_ip(self) -> str:
    return self._modem_ip

  def process_callbacks(self):
    to_run, self._callback_queue = self._callback_queue, []
    for cb in to_run:
      cb()

    now = time.monotonic()
    if now - self._last_ip_poll >= MODEM_IP_POLL_INTERVAL:
      self._last_ip_poll = now
      self._modem_ip = _get_modem_ip()

  @property
  def profiles(self) -> list[Profile]:
    return self._profiles

  @property
  def busy(self) -> bool:
    return self._busy

  @property
  def switching_iccid(self) -> str | None:
    return self._switching_iccid

  def is_comma_profile(self, iccid: str) -> bool:
    return any(p.iccid == iccid and p.provider == 'Webbing' for p in self._profiles)

  def _ensure_lpa(self) -> LPABase:
    if self._lpa is None:
      self._lpa = _get_lpa()
    return self._lpa

  def _finish(self, profiles: list[Profile] | None = None, error: str | None = None):
    self._busy = False
    self._switching_iccid = None
    if profiles is not None:
      self._profiles = profiles
      for cb in self._profiles_updated_cbs:
        cb(profiles)
    if error is not None:
      for cb in self._operation_error_cbs:
        cb(error)

  def _run_operation(self, fn: Callable, error_msg: str):
    self._busy = True

    def worker():
      try:
        with self._lock:
          lpa = self._ensure_lpa()
          fn(lpa)
          profiles = lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish(profiles=profiles))
      except Exception as e:
        cloudlog.exception(error_msg)
        err = str(e)
        self._callback_queue.append(lambda: self._finish(error=err))

    threading.Thread(target=worker, daemon=True).start()

  def refresh_profiles(self):
    def worker():
      try:
        with self._lock:
          lpa = self._ensure_lpa()
          lpa.process_notifications()
          profiles = lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish(profiles=profiles))
      except Exception:
        cloudlog.exception("Failed to list eSIM profiles")
        time.sleep(LPA_RETRY_INTERVAL)
        self._callback_queue.append(lambda: self.refresh_profiles())

    threading.Thread(target=worker, daemon=True).start()

  def switch_profile(self, iccid: str):
    self._switching_iccid = iccid
    self._run_operation(lambda lpa: lpa.switch_profile(iccid), "Failed to switch eSIM profile")

  def delete_profile(self, iccid: str):
    self._run_operation(lambda lpa: lpa.delete_profile(iccid), "Failed to delete eSIM profile")

  def download_profile(self, qr: str, nickname: str | None = None):
    self._busy = True

    def worker():
      try:
        with self._lock:
          lpa = self._ensure_lpa()
          lpa.download_profile(qr, nickname)
          profiles = lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish(profiles=profiles))
      except Exception as e:
        cloudlog.exception("Failed to download eSIM profile")
        err = str(e)
        self._callback_queue.append(lambda: self._finish(error=err))

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    def watchdog():
      t.join(timeout=DOWNLOAD_TIMEOUT)
      if t.is_alive():
        cloudlog.error("eSIM profile download timed out")
        self._callback_queue.append(lambda: self._finish(error="Profile download timed out. Please try again."))

    threading.Thread(target=watchdog, daemon=True).start()

  def nickname_profile(self, iccid: str, nickname: str):
    self._run_operation(lambda lpa: lpa.nickname_profile(iccid, nickname), "Failed to update eSIM profile nickname")
