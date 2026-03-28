import time
import threading
from collections.abc import Callable

from openpilot.common.swaglog import cloudlog
from openpilot.system.hardware.base import LPABase, Profile


class MockLPA(LPABase):
  """Mock LPA for desktop development with fake profiles."""

  def __init__(self):
    self._profiles: list[Profile] = [
      Profile(iccid="8901234567890123456", nickname="", enabled=True, provider="Webbing"),
      Profile(iccid="8904567890123456789", nickname="Personal", enabled=False, provider="T-Mobile"),
      Profile(iccid="8907890123456789012", nickname="Travel eSIM", enabled=False, provider="Airalo"),
    ]

  def list_profiles(self) -> list[Profile]:
    return list(self._profiles)

  def get_active_profile(self) -> Profile | None:
    return next((p for p in self._profiles if p.enabled), None)

  def delete_profile(self, iccid: str) -> None:
    time.sleep(2)
    self._profiles = [p for p in self._profiles if p.iccid != iccid]

  def download_profile(self, qr: str, nickname: str | None = None) -> None:
    time.sleep(2)
    self._profiles.append(Profile(
      iccid=f"890{int(time.time())}",
      nickname=nickname or "",
      enabled=False,
      provider="New Profile",
    ))

  def nickname_profile(self, iccid: str, nickname: str) -> None:
    time.sleep(1)
    self._profiles = [
      Profile(iccid=p.iccid, nickname=nickname if p.iccid == iccid else p.nickname, enabled=p.enabled, provider=p.provider)
      for p in self._profiles
    ]

  def switch_profile(self, iccid: str) -> None:
    time.sleep(2)
    self._profiles = [
      Profile(iccid=p.iccid, nickname=p.nickname, enabled=(p.iccid == iccid), provider=p.provider)
      for p in self._profiles
    ]


def _get_lpa() -> LPABase:
  try:
    from openpilot.system.hardware import HARDWARE
    return HARDWARE.get_sim_lpa()
  except Exception:
    return MockLPA()


class ESimManager:
  def __init__(self):
    self._lpa: LPABase = _get_lpa()
    self._profiles: list[Profile] = []
    self._busy: bool = False
    self._switching_iccid: str | None = None
    self._lock = threading.Lock()
    self._callback_queue: list[Callable] = []

    self._profiles_updated_cbs: list[Callable[[list[Profile]], None]] = []
    self._operation_error_cbs: list[Callable[[str], None]] = []

  def add_callbacks(self, profiles_updated: Callable | None = None, operation_error: Callable | None = None):
    if profiles_updated:
      self._profiles_updated_cbs.append(profiles_updated)
    if operation_error:
      self._operation_error_cbs.append(operation_error)

  def process_callbacks(self):
    to_run, self._callback_queue = self._callback_queue, []
    for cb in to_run:
      cb()

  def _enqueue_callbacks(self, cbs: list, *args):
    for cb in cbs:
      self._callback_queue.append(lambda _cb=cb, _args=args: _cb(*_args))

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

  def refresh_profiles(self):
    def worker():
      try:
        with self._lock:
          profiles = self._lpa.list_profiles()
        self._profiles = profiles
        self._enqueue_callbacks(self._profiles_updated_cbs, profiles)
      except Exception as e:
        cloudlog.exception("Failed to list eSIM profiles")
        self._enqueue_callbacks(self._operation_error_cbs, str(e))

    threading.Thread(target=worker, daemon=True).start()

  def _finish_switch(self, profiles: list[Profile] | None = None, error: str | None = None):
    """Called on UI thread via callback queue to atomically clear switch state."""
    self._busy = False
    self._switching_iccid = None
    if profiles is not None:
      self._profiles = profiles
      for cb in self._profiles_updated_cbs:
        cb(profiles)
    if error is not None:
      for cb in self._operation_error_cbs:
        cb(error)

  def switch_profile(self, iccid: str):
    self._busy = True
    self._switching_iccid = iccid

    def worker():
      try:
        with self._lock:
          self._lpa.switch_profile(iccid)
          profiles = self._lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish_switch(profiles=profiles))
      except Exception as e:
        cloudlog.exception("Failed to switch eSIM profile")
        self._callback_queue.append(lambda: self._finish_switch(error=str(e)))

    threading.Thread(target=worker, daemon=True).start()

  def _finish_operation(self, profiles: list[Profile] | None = None, error: str | None = None):
    """Called on UI thread via callback queue to atomically clear busy state."""
    self._busy = False
    if profiles is not None:
      self._profiles = profiles
      for cb in self._profiles_updated_cbs:
        cb(profiles)
    if error is not None:
      for cb in self._operation_error_cbs:
        cb(error)

  def delete_profile(self, iccid: str):
    self._busy = True

    def worker():
      try:
        with self._lock:
          self._lpa.delete_profile(iccid)
          profiles = self._lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish_operation(profiles=profiles))
      except Exception as e:
        cloudlog.exception("Failed to delete eSIM profile")
        self._callback_queue.append(lambda: self._finish_operation(error=str(e)))

    threading.Thread(target=worker, daemon=True).start()

  def download_profile(self, qr: str, nickname: str | None = None):
    self._busy = True

    def worker():
      try:
        with self._lock:
          self._lpa.download_profile(qr, nickname)
          profiles = self._lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish_operation(profiles=profiles))
      except Exception as e:
        cloudlog.exception("Failed to download eSIM profile")
        self._callback_queue.append(lambda: self._finish_operation(error=str(e)))

    threading.Thread(target=worker, daemon=True).start()

  def nickname_profile(self, iccid: str, nickname: str):
    self._busy = True

    def worker():
      try:
        with self._lock:
          self._lpa.nickname_profile(iccid, nickname)
          profiles = self._lpa.list_profiles()
        self._callback_queue.append(lambda: self._finish_operation(profiles=profiles))
      except Exception as e:
        cloudlog.exception("Failed to update eSIM profile nickname")
        self._callback_queue.append(lambda: self._finish_operation(error=str(e)))

    threading.Thread(target=worker, daemon=True).start()
