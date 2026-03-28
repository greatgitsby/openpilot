import threading
import urllib.request
from enum import IntEnum
from functools import partial

import pyray as rl

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.application import gui_app, FontWeight
from openpilot.system.ui.lib.cellular_manager import CellularManager
from openpilot.system.ui.lib.scroll_panel import GuiScrollPanel
from openpilot.system.hardware.base import Profile
from openpilot.system.ui.widgets import DialogResult, Widget
from openpilot.system.ui.widgets.button import ButtonStyle, Button
from openpilot.system.ui.widgets.confirm_dialog import ConfirmDialog, alert_dialog
from openpilot.system.ui.widgets.keyboard import Keyboard
from openpilot.system.ui.widgets.label import gui_label

try:
  from pyzbar.pyzbar import decode as pyzbar_decode
  from msgq.visionipc import VisionStreamType
  from openpilot.selfdrive.ui.onroad.cameraview import CameraView
  from openpilot.common.params import Params
  from openpilot.selfdrive.ui.ui_state import device
except Exception:
  pyzbar_decode = None
  VisionStreamType = None
  CameraView = None
  Params = None
  device = None

ITEM_HEIGHT = 160
ICON_SIZE = 50
MAX_NICKNAME_LENGTH = 64


class UIState(IntEnum):
  IDLE = 0
  SWITCHING = 1
  DELETING = 2
  DOWNLOADING = 3


def _profile_display_name(profile: Profile) -> str:
  name = profile.nickname or profile.provider or profile.iccid[:12]
  suffix = profile.iccid[-4:]
  return f"{name} (...{suffix})"


def _is_valid_lpa_code(text: str) -> bool:
  if not text.startswith("LPA:"):
    return False
  parts = text[4:].split("$")
  return len(parts) == 3 and all(parts)


class QRScannerDialog(Widget):
  def __init__(self, on_qr_detected):
    super().__init__()
    self._on_qr_detected = on_qr_detected
    self._camera_view = CameraView("camerad", VisionStreamType.VISION_STREAM_DRIVER) if CameraView else None
    self._detected = False
    self._scan_thread: threading.Thread | None = None
    self._scan_result: str | None = None

  def show_event(self):
    super().show_event()
    if Params:
      Params().put_bool("IsDriverViewEnabled", True)

  def hide_event(self):
    super().hide_event()
    if Params:
      Params().put_bool("IsDriverViewEnabled", False)

  def __del__(self):
    if self._camera_view:
      self._camera_view.close()

  def _update_state(self):
    super()._update_state()
    if self._camera_view:
      self._camera_view._update_state()

    if self._detected or not self._camera_view or not self._camera_view.frame:
      return

    # Check for result from background scan
    if self._scan_result is not None:
      data = self._scan_result
      self._scan_result = None
      if _is_valid_lpa_code(data):
        self._detected = True
        gui_app.pop_widget()
        self._on_qr_detected(data)
        return

    # Launch scan in background if not already running
    if self._scan_thread is None or not self._scan_thread.is_alive():
      frame = self._camera_view.frame
      gray = frame.data[:frame.height * frame.stride].reshape(frame.height, frame.stride)[:, :frame.width]
      h, w = gray.shape
      gray = gray[h // 4: 3 * h // 4, w // 4: 3 * w // 4]
      gray = gray[::2, ::2].copy()

      def scan():
        results = pyzbar_decode(gray)
        if results:
          self._scan_result = results[0].data.decode('utf-8')

      self._scan_thread = threading.Thread(target=scan, daemon=True)
      self._scan_thread.start()

  def _render(self, rect):
    rl.begin_scissor_mode(int(rect.x), int(rect.y), int(rect.width), int(rect.height))

    if self._camera_view:
      self._camera_view._render(rect)

    if not self._camera_view or not self._camera_view.frame:
      gui_label(rect, "Camera starting...", font_size=54, font_weight=FontWeight.BOLD,
                alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
    else:
      # Draw scan region border
      crop_rect = rl.Rectangle(rect.x + rect.width / 4, rect.y + rect.height / 4,
                                rect.width / 2, rect.height / 2)
      rl.draw_rectangle_lines_ex(crop_rect, 3, rl.Color(255, 255, 255, 150))

      label_y = rect.y + rect.height * 3 / 4
      label_rect = rl.Rectangle(rect.x, label_y + (rect.height - label_y) / 2 - 20, rect.width, 40)
      gui_label(label_rect, "Hold QR code to camera", font_size=32, font_weight=FontWeight.MEDIUM,
                alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
                color=rl.Color(255, 255, 255, int(255 * 0.9)))

    rl.end_scissor_mode()

  def _handle_mouse_release(self, mouse_pos):
    # Tap anywhere to dismiss
    gui_app.pop_widget()


class InstallingDialog(Widget):
  DOT_STEP = 0.6

  def __init__(self):
    super().__init__()
    self._show_time = 0.0

  def show_event(self):
    super().show_event()
    self._show_time = rl.get_time()

  def _render(self, rect):
    # Keep screen awake during profile installation
    if device:
      device._reset_interactive_timeout()

    rl.draw_rectangle_rec(rl.Rectangle(0, 0, gui_app.width, gui_app.height), rl.Color(27, 27, 27, 255))
    t = (rl.get_time() - self._show_time) % (self.DOT_STEP * 2)
    dots = "." * min(int(t / (self.DOT_STEP / 4)), 3)
    gui_label(rl.Rectangle(0, 0, gui_app.width, gui_app.height - 80),
              "Installing eSIM Profile", font_size=70, font_weight=FontWeight.BOLD,
              alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
    gui_label(rl.Rectangle(0, 80, gui_app.width, gui_app.height),
              f"Please wait{dots}", font_size=55,
              alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
              color=rl.Color(170, 170, 170, 255))


class ESimManagerUI(Widget):
  def __init__(self, cellular_manager: CellularManager):
    super().__init__()
    self._cellular_manager = cellular_manager
    self.state: UIState = UIState.IDLE
    self._state_iccid: str | None = None
    self.scroll_panel = GuiScrollPanel()
    self.keyboard = Keyboard(max_text_size=MAX_NICKNAME_LENGTH, min_text_size=0)

    self._profiles: list[Profile] = []
    self._profile_buttons: dict[str, Button] = {}
    self._forget_buttons: dict[str, Button] = {}
    self._add_button = Button("Add eSIM", self._on_add_profile, font_size=55, button_style=ButtonStyle.PRIMARY)

    self._installing_dialog: InstallingDialog | None = None
    self._pending_lpa_code: str | None = None

    self._cellular_manager.add_callbacks(
      profiles_updated=self._on_profiles_updated,
      operation_error=self._on_error,
    )

  def show_event(self):
    super().show_event()
    self._on_profiles_updated(self._cellular_manager.profiles)
    self._cellular_manager.refresh_profiles()
    gui_app.add_nav_stack_tick(self._cellular_manager.process_callbacks)

  def hide_event(self):
    super().hide_event()
    gui_app.remove_nav_stack_tick(self._cellular_manager.process_callbacks)

  def _update_state(self):
    self._cellular_manager.process_callbacks()

  def _on_profiles_updated(self, profiles: list[Profile]):
    if self._installing_dialog:
      gui_app.pop_widget()
      self._installing_dialog = None

    self._profiles = profiles
    self._profile_buttons.clear()
    self._forget_buttons.clear()

    for p in self._profiles:
      display = _profile_display_name(p)
      self._profile_buttons[p.iccid] = Button(display, partial(self._on_profile_clicked, p.iccid), font_size=55,
                                                text_alignment=rl.GuiTextAlignment.TEXT_ALIGN_LEFT,
                                                button_style=ButtonStyle.TRANSPARENT_WHITE_TEXT)
      self._profile_buttons[p.iccid].set_touch_valid_callback(lambda: self.scroll_panel.is_touch_valid())

      if not p.enabled and not self._cellular_manager.is_comma_profile(p.iccid):
        self._forget_buttons[p.iccid] = Button("Forget", partial(self._on_forget_clicked, p.iccid),
                                                button_style=ButtonStyle.FORGET_WIFI, font_size=45)
        self._forget_buttons[p.iccid].set_touch_valid_callback(lambda: self.scroll_panel.is_touch_valid())

    if self.state == UIState.SWITCHING or self.state == UIState.DELETING:
      self.state = UIState.IDLE
      self._state_iccid = None

  def _on_error(self, error: str):
    if self._installing_dialog:
      gui_app.pop_widget()
      self._installing_dialog = None

    self.state = UIState.IDLE
    self._state_iccid = None
    gui_app.push_widget(alert_dialog(error))

  def _render(self, rect: rl.Rectangle):
    if not self._profiles:
      gui_label(rect, "Loading eSIM profiles...", 72, alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
      return

    # Total items: profiles + add button
    total_items = len(self._profiles) + 1
    content_rect = rl.Rectangle(rect.x, rect.y, rect.width, total_items * ITEM_HEIGHT)
    offset = self.scroll_panel.update(rect, content_rect)

    rl.begin_scissor_mode(int(rect.x), int(rect.y), int(rect.width), int(rect.height))
    for i, profile in enumerate(self._profiles):
      y_offset = rect.y + i * ITEM_HEIGHT + offset
      item_rect = rl.Rectangle(rect.x, y_offset, rect.width, ITEM_HEIGHT)
      if not rl.check_collision_recs(item_rect, rect):
        continue

      self._draw_profile_item(item_rect, profile)
      line_y = int(item_rect.y + item_rect.height - 1)
      rl.draw_line(int(item_rect.x), line_y, int(item_rect.x + item_rect.width), line_y, rl.LIGHTGRAY)

    # Add button at the bottom
    add_y = rect.y + len(self._profiles) * ITEM_HEIGHT + offset
    add_rect = rl.Rectangle(rect.x + rect.width / 2 - 200, add_y + (ITEM_HEIGHT - 80) / 2, 400, 80)
    if rl.check_collision_recs(rl.Rectangle(rect.x, add_y, rect.width, ITEM_HEIGHT), rect):
      self._add_button.set_enabled(not self._cellular_manager.busy)
      self._add_button.render(add_rect)

    rl.end_scissor_mode()

  def _draw_profile_item(self, rect: rl.Rectangle, profile: Profile):
    btn_width = 200
    spacing = 50
    ssid_rect = rl.Rectangle(rect.x, rect.y, rect.width - btn_width * 2, ITEM_HEIGHT)

    status_text = ""
    if self.state == UIState.SWITCHING and self._state_iccid == profile.iccid:
      self._profile_buttons[profile.iccid].set_enabled(False)
      status_text = "SWITCHING..."
    elif self.state == UIState.DELETING and self._state_iccid == profile.iccid:
      self._profile_buttons[profile.iccid].set_enabled(False)
      status_text = "DELETING..."
    elif profile.enabled:
      status_text = "ACTIVE"
    else:
      self._profile_buttons[profile.iccid].set_enabled(True)

    self._profile_buttons[profile.iccid].render(ssid_rect)

    if status_text:
      status_rect = rl.Rectangle(rect.x + rect.width - 410 - spacing, rect.y, 410, ITEM_HEIGHT)
      gui_label(status_rect, status_text, font_size=48, alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
    elif profile.iccid in self._forget_buttons:
      forget_rect = rl.Rectangle(
        rect.x + rect.width - btn_width - spacing,
        rect.y + (ITEM_HEIGHT - 80) / 2,
        btn_width, 80,
      )
      self._forget_buttons[profile.iccid].render(forget_rect)

  def _on_profile_clicked(self, iccid: str):
    profile = next((p for p in self._profiles if p.iccid == iccid), None)
    if profile is None:
      return

    if profile.enabled:
      # Edit nickname
      current_name = profile.nickname or ""
      self.keyboard.reset(min_text_size=0)
      self.keyboard.set_title("Enter nickname", f"for \"{_profile_display_name(profile)}\"")
      self.keyboard.set_text(current_name)
      self.keyboard.set_callback(lambda result: self._on_nickname_entered(iccid, result))
      gui_app.push_widget(self.keyboard)
    else:
      # Switch to profile
      self.state = UIState.SWITCHING
      self._state_iccid = iccid
      self._cellular_manager.switch_profile(iccid)

  def _on_nickname_entered(self, iccid: str, result: DialogResult):
    if result == DialogResult.CONFIRM:
      nickname = self.keyboard.text.strip()
      self._cellular_manager.nickname_profile(iccid, nickname)

  def _on_forget_clicked(self, iccid: str):
    profile = next((p for p in self._profiles if p.iccid == iccid), None)
    if profile is None:
      return

    name = _profile_display_name(profile)
    confirm = ConfirmDialog(f"Delete eSIM profile \"{name}\"?", "Delete", "Cancel",
                            callback=lambda result: self._on_forget_confirmed(iccid, result))
    gui_app.push_widget(confirm)

  def _on_forget_confirmed(self, iccid: str, result: DialogResult):
    if result == DialogResult.CONFIRM:
      self.state = UIState.DELETING
      self._state_iccid = iccid
      self._cellular_manager.delete_profile(iccid)

  def _on_add_profile(self):
    if not CameraView or not pyzbar_decode:
      gui_app.push_widget(alert_dialog("QR scanning not available on this platform"))
      return

    scanner = QRScannerDialog(on_qr_detected=self._on_qr_scanned)
    gui_app.push_widget(scanner)

  def _on_qr_scanned(self, lpa_code: str):
    self._pending_lpa_code = lpa_code
    print(f"[esim] QR scanned: {lpa_code[:30]}...", flush=True)

    def check_connectivity():
      try:
        req = urllib.request.Request("https://openpilot.comma.ai", method="HEAD")
        urllib.request.urlopen(req, timeout=2.0)
        connected = True
      except Exception as e:
        print(f"[esim] connectivity check failed: {e}", flush=True)
        connected = False
      print(f"[esim] connectivity: {connected}", flush=True)
      self._cellular_manager._callback_queue.append(
        lambda: self._start_download() if connected else self._on_error("No internet connection.\nConnect to Wi-Fi or cellular to install.")
      )

    threading.Thread(target=check_connectivity, daemon=True).start()

  def _start_download(self):
    print(f"[esim] starting download", flush=True)
    self._installing_dialog = InstallingDialog()
    gui_app.push_widget(self._installing_dialog)
    self._cellular_manager.download_profile(self._pending_lpa_code)
