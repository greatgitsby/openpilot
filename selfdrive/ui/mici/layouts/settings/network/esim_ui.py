import threading
import urllib.request

from pyzbar.pyzbar import decode as pyzbar_decode
import pyray as rl
from collections.abc import Callable
from msgq.visionipc import VisionStreamType

from openpilot.system.ui.lib.cellular_manager import CellularManager
from openpilot.selfdrive.ui.mici.onroad.cameraview import CameraView
from openpilot.selfdrive.ui.mici.widgets.button import BigButton, LABEL_COLOR
from openpilot.selfdrive.ui.mici.widgets.dialog import BigConfirmationDialog, BigDialog, BigInputDialog
from openpilot.selfdrive.ui.ui_state import ui_state
from openpilot.system.hardware.base import Profile
from openpilot.system.ui.lib.application import gui_app, FontWeight, MousePos
from openpilot.system.ui.lib.multilang import tr
from openpilot.system.ui.widgets import Widget
from openpilot.system.ui.widgets.label import gui_label
from openpilot.system.ui.widgets.nav_widget import NavWidget
from openpilot.system.ui.widgets.scroller import NavScroller


class DeleteButton(Widget):
  MARGIN = 12

  def __init__(self, delete_callback: Callable):
    super().__init__()
    self._delete_callback = delete_callback

    self._bg_txt = gui_app.texture("icons_mici/settings/network/new/forget_button.png", 84, 84)
    self._bg_pressed_txt = gui_app.texture("icons_mici/settings/network/new/forget_button_pressed.png", 84, 84)
    self._trash_txt = gui_app.texture("icons_mici/settings/network/new/trash.png", 29, 35)
    self.set_rect(rl.Rectangle(0, 0, 84 + self.MARGIN * 2, 84 + self.MARGIN * 2))

  def _handle_mouse_release(self, mouse_pos: MousePos):
    super()._handle_mouse_release(mouse_pos)
    dlg = BigConfirmationDialog("slide to delete", gui_app.texture("icons_mici/settings/network/new/trash.png", 54, 64),
                                self._delete_callback, red=True)
    gui_app.push_widget(dlg)

  def _render(self, _):
    bg_txt = self._bg_pressed_txt if self.is_pressed else self._bg_txt
    rl.draw_texture_ex(bg_txt, (self._rect.x + (self._rect.width - self._bg_txt.width) / 2,
                                self._rect.y + (self._rect.height - self._bg_txt.height) / 2), 0, 1.0, rl.WHITE)

    trash_x = self._rect.x + (self._rect.width - self._trash_txt.width) / 2
    trash_y = self._rect.y + (self._rect.height - self._trash_txt.height) / 2
    rl.draw_texture_ex(self._trash_txt, (trash_x, trash_y), 0, 1.0, rl.WHITE)


def _profile_display_name(profile: Profile) -> str:
  name = profile.nickname or profile.provider or profile.iccid[:12]
  suffix = profile.iccid[-4:]
  return f"{name} (...{suffix})"


def _is_valid_lpa_code(text: str) -> bool:
  if not text.startswith("LPA:"):
    return False
  parts = text[4:].split("$")
  return len(parts) == 3 and all(parts)


class QRScannerDialog(NavWidget):
  def __init__(self, on_qr_detected: Callable[[str], None]):
    super().__init__()
    self._on_qr_detected = on_qr_detected
    self._camera_view = CameraView("camerad", VisionStreamType.VISION_STREAM_DRIVER)
    self._detected = False
    self._scan_thread: threading.Thread | None = None
    self._scan_result: str | None = None
    self.set_rect(rl.Rectangle(0, 0, gui_app.width, gui_app.height))

  def show_event(self):
    super().show_event()
    ui_state.params.put_bool("IsDriverViewEnabled", True)

  def hide_event(self):
    super().hide_event()
    ui_state.params.put_bool("IsDriverViewEnabled", False)

  def __del__(self):
    self._camera_view.close()

  def _update_state(self):
    super()._update_state()
    self._camera_view._update_state()

    if self._detected or not self._camera_view.frame:
      return

    # Check for result from background scan
    if self._scan_result is not None:
      data = self._scan_result
      self._scan_result = None
      if _is_valid_lpa_code(data):
        self._detected = True
        self.dismiss(lambda: self._on_qr_detected(data))
        return

    # Launch scan in background if not already running
    if self._scan_thread is None or not self._scan_thread.is_alive():
      frame = self._camera_view.frame
      gray = frame.data[:frame.height * frame.stride].reshape(frame.height, frame.stride)[:, :frame.width]
      h, w = gray.shape
      gray = gray[h // 4 : 3 * h // 4, w // 4 : 3 * w // 4: ]
      gray = gray[::2, ::2].copy()

      def scan():
        results = pyzbar_decode(gray)
        if results:
          self._scan_result = results[0].data.decode('utf-8')

      self._scan_thread = threading.Thread(target=scan, daemon=True)
      self._scan_thread.start()

  def _render(self, rect):
    rl.begin_scissor_mode(int(rect.x), int(rect.y), int(rect.width), int(rect.height))
    self._camera_view._render(rect)

    if not self._camera_view.frame:
      gui_label(rect, tr("camera starting"), font_size=100, font_weight=FontWeight.BOLD,
                alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
    else:
      # Draw scan region border
      crop_rect = rl.Rectangle(rect.x + rect.width / 4, rect.y + rect.height / 4,
                                rect.width / 2, rect.height / 2)
      rl.draw_rectangle_lines_ex(crop_rect, 3, rl.Color(255, 255, 255, 150))

      label_y = rect.y + rect.height * 3 / 4
      label_rect = rl.Rectangle(rect.x, label_y + (rect.height - label_y) / 2 - 20, rect.width, 40)
      gui_label(label_rect, "hold QR code to camera", font_size=32, font_weight=FontWeight.MEDIUM,
                alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
                color=rl.Color(255, 255, 255, int(255 * 0.9)))

    rl.end_scissor_mode()


class InstallingProfileDialog(BigDialog):
  DOT_STEP = 0.6

  def __init__(self):
    super().__init__("installing profile", "please wait...")
    self._show_time = 0.0

  def show_event(self):
    super().show_event()
    self._nav_bar._alpha = 0.0
    self._show_time = rl.get_time()

  def _back_enabled(self) -> bool:
    return False

  def _render(self, _):
    t = (rl.get_time() - self._show_time) % (self.DOT_STEP * 2)
    dots = "." * min(int(t / (self.DOT_STEP / 4)), 3)
    self._card.set_value(f"please wait{dots}")
    super()._render(_)


class ESimProfileButton(BigButton):
  LABEL_PADDING = 98
  LABEL_WIDTH = 402 - 98 - 28
  SUB_LABEL_WIDTH = 402 - BigButton.LABEL_HORIZONTAL_PADDING * 2

  def __init__(self, profile: Profile, cellular_manager: CellularManager):
    self._cellular_manager = cellular_manager
    is_comma = cellular_manager.is_comma_profile(profile.iccid)
    display_name = "comma.ai" if is_comma else _profile_display_name(profile)
    super().__init__(display_name, scroll=True)

    self._profile = profile
    self._deleting = False

    self._cell_full_txt = gui_app.texture("icons_mici/settings/network/cell_strength_full.png", 48, 36)
    self._cell_none_txt = gui_app.texture("icons_mici/settings/network/cell_strength_none.png", 48, 36)
    self._check_txt = gui_app.texture("icons_mici/setup/driver_monitoring/dm_check.png", 32, 32)
    self._comma_txt = gui_app.texture("icons_mici/settings/comma_icon.png", 36, 36) if is_comma else None

    self._delete_btn = DeleteButton(self._on_delete)

  @property
  def profile(self) -> Profile:
    return self._profile

  def update_profile(self, profile: Profile):
    self._profile = profile
    self._deleting = False
    is_comma = self._cellular_manager.is_comma_profile(profile.iccid)
    self.set_text("comma.ai" if is_comma else _profile_display_name(profile))

  @property
  def _show_delete_btn(self) -> bool:
    if self._deleting or self._profile.enabled:
      return False
    return not self._cellular_manager.is_comma_profile(self._profile.iccid)

  def _on_delete(self):
    if self._deleting:
      return
    self._deleting = True
    self._cellular_manager.delete_profile(self._profile.iccid)

  def _handle_mouse_release(self, mouse_pos: MousePos):
    if self._show_delete_btn and rl.check_collision_point_rec(mouse_pos, self._delete_btn.rect):
      return
    super()._handle_mouse_release(mouse_pos)

  def _get_label_font_size(self):
    return 48

  def _draw_content(self, btn_y: float):
    self._label.set_color(LABEL_COLOR)
    label_rect = rl.Rectangle(self._rect.x + self.LABEL_PADDING, btn_y + self.LABEL_VERTICAL_PADDING,
                              self.LABEL_WIDTH, self._rect.height - self.LABEL_VERTICAL_PADDING * 2)
    self._label.render(label_rect)

    if self.value:
      sub_label_x = self._rect.x + self.LABEL_HORIZONTAL_PADDING
      label_y = btn_y + self._rect.height - self.LABEL_VERTICAL_PADDING
      sub_label_w = self.SUB_LABEL_WIDTH - (self._delete_btn.rect.width if self._show_delete_btn else 0)
      sub_label_height = self._sub_label.get_content_height(sub_label_w)

      if self._profile.enabled and not self._deleting:
        check_y = int(label_y - sub_label_height + (sub_label_height - self._check_txt.height) / 2)
        rl.draw_texture_ex(self._check_txt, rl.Vector2(sub_label_x, check_y), 0.0, 1.0, rl.Color(255, 255, 255, int(255 * 0.9 * 0.65)))
        sub_label_x += self._check_txt.width + 14

      sub_label_rect = rl.Rectangle(sub_label_x, label_y - sub_label_height, sub_label_w, sub_label_height)
      self._sub_label.render(sub_label_rect)

    # Cell icon (comma icon for comma profiles)
    if self._comma_txt:
      rl.draw_texture_ex(self._comma_txt, (self._rect.x + 36, btn_y + 30, ), 0.0, 1.0, rl.WHITE)
    else:
      cell_icon = self._cell_full_txt if self._profile.enabled else self._cell_none_txt
      rl.draw_texture_ex(cell_icon, (self._rect.x + 30, btn_y + 30, ), 0.0, 1.0, rl.WHITE)

    # Delete button
    if self._show_delete_btn:
      self._delete_btn.render(rl.Rectangle(
        self._rect.x + self._rect.width - self._delete_btn.rect.width,
        btn_y + self._rect.height - self._delete_btn.rect.height,
        self._delete_btn.rect.width,
        self._delete_btn.rect.height,
      ))

  def set_touch_valid_callback(self, touch_callback: Callable[[], bool]) -> None:
    super().set_touch_valid_callback(lambda: touch_callback() and not self._delete_btn.is_pressed)
    self._delete_btn.set_touch_valid_callback(touch_callback)

  def _update_state(self):
    super()._update_state()

    if self._cellular_manager.busy or self._deleting:
      self.set_enabled(False)
      self._sub_label.set_color(rl.Color(255, 255, 255, int(255 * 0.585)))
      self._sub_label.set_font_weight(FontWeight.ROMAN)

      if self._deleting:
        self.set_value("deleting...")
      elif self._cellular_manager.busy:
        self.set_value("switching..." if not self._profile.enabled else "active")
    elif self._profile.enabled:
      self.set_value("active")
      self.set_enabled(True)
      self._sub_label.set_color(rl.Color(255, 255, 255, int(255 * 0.585)))
      self._sub_label.set_font_weight(FontWeight.ROMAN)
    else:
      self.set_value("switch")
      self.set_enabled(True)
      self._sub_label.set_color(rl.Color(255, 255, 255, int(255 * 0.9)))
      self._sub_label.set_font_weight(FontWeight.SEMI_BOLD)


class ESimUIMici(NavScroller):
  def __init__(self, cellular_manager: CellularManager):
    super().__init__()

    self._cellular_manager = cellular_manager
    self._add_profile_btn = BigButton("add profile", "scan QR code")
    self._add_profile_btn.set_click_callback(self._on_add_profile)
    self._installing_dialog: InstallingProfileDialog | None = None

    self._cellular_manager.add_callbacks(
      profiles_updated=self._on_profiles_updated,
      operation_error=self._on_error,
    )

  def show_event(self):
    super().show_event()
    self._on_profiles_updated(self._cellular_manager.profiles)
    self._cellular_manager.refresh_profiles()

  def _on_profiles_updated(self, profiles: list[Profile]):
    if self._installing_dialog:
      self._installing_dialog.dismiss()
      self._installing_dialog = None

    existing = {btn.profile.iccid: btn for btn in self._scroller.items if isinstance(btn, ESimProfileButton)}

    current_iccids = {p.iccid for p in profiles}

    # Update existing and add new
    for profile in profiles:
      if profile.iccid in existing:
        existing[profile.iccid].update_profile(profile)
      else:
        btn = ESimProfileButton(profile, self._cellular_manager)
        btn.set_click_callback(lambda iccid=profile.iccid: self._on_profile_clicked(iccid))
        self._scroller.add_widget(btn)

    # Remove deleted profiles
    self._scroller.items[:] = [
      btn for btn in self._scroller.items
      if not isinstance(btn, ESimProfileButton) or btn.profile.iccid in current_iccids
    ]

    # Keep add button at the end
    if self._add_profile_btn in self._scroller.items:
      self._scroller.items.append(self._scroller.items.pop(self._scroller.items.index(self._add_profile_btn)))
    else:
      self._scroller.add_widget(self._add_profile_btn)

  def _move_profile_to_front(self, iccid: str | None, scroll: bool = False):
    if iccid is None:
      return

    front_btn_idx = next((i for i, btn in enumerate(self._scroller.items)
                          if isinstance(btn, ESimProfileButton) and
                          btn.profile.iccid == iccid), None)

    if front_btn_idx is not None and front_btn_idx > 0:
      self._scroller.move_item(front_btn_idx, 0)

      if scroll:
        self._scroller.scroll_to(self._scroller.scroll_panel.get_offset(), smooth=True)

  def _update_state(self):
    super()._update_state()
    self._add_profile_btn.set_enabled(not self._cellular_manager.busy)

    # Keep the switching/active profile at the front with animation
    iccid = self._cellular_manager.switching_iccid
    if iccid is None:
      active = next((p for p in self._cellular_manager.profiles if p.enabled), None)
      iccid = active.iccid if active else None
    self._move_profile_to_front(iccid)

  def _on_add_profile(self):
    scanner = QRScannerDialog(on_qr_detected=self._on_qr_scanned)
    gui_app.push_widget(scanner)

  def _on_qr_scanned(self, lpa_code: str):
    self._pending_lpa_code = lpa_code
    self._installing_dialog = InstallingProfileDialog()
    gui_app.push_widget(self._installing_dialog)

    def check_connectivity():
      try:
        req = urllib.request.Request("https://openpilot.comma.ai", method="HEAD")
        urllib.request.urlopen(req, timeout=2.0)
        connected = True
      except Exception:
        connected = False
      self._cellular_manager._callback_queue.append(
        lambda: self._cellular_manager.download_profile(self._pending_lpa_code) if connected else self._on_error("no internet connection\nconnect to wifi or\ncellular to install")
      )

    threading.Thread(target=check_connectivity, daemon=True).start()

  def _on_error(self, error: str):
    if self._installing_dialog:
      self._installing_dialog.dismiss(lambda: gui_app.push_widget(BigDialog("esim error", error)))
      self._installing_dialog = None
    else:
      dlg = BigDialog("esim error", error)
      gui_app.push_widget(dlg)

  def _on_profile_clicked(self, iccid: str):
    profile = next((p for p in self._cellular_manager.profiles if p.iccid == iccid), None)
    if profile is None:
      return

    if profile.enabled and not self._cellular_manager.is_comma_profile(iccid):
      # Edit nickname
      current_name = profile.nickname or ""
      dlg = BigInputDialog("enter nickname...", current_name, minimum_length=0,
                           confirm_callback=lambda name: self._cellular_manager.nickname_profile(iccid, name))
      gui_app.push_widget(dlg)
    else:
      # Switch to profile immediately
      self._cellular_manager.switch_profile(iccid)
      self._move_profile_to_front(iccid, scroll=True)
