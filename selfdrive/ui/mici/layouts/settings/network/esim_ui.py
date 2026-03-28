import pyray as rl
from collections.abc import Callable

from openpilot.selfdrive.ui.mici.layouts.settings.network.esim_manager import ESimManager
from openpilot.selfdrive.ui.mici.widgets.button import BigButton, LABEL_COLOR
from openpilot.selfdrive.ui.mici.widgets.dialog import BigConfirmationDialog, BigInputDialog
from openpilot.system.hardware.base import Profile
from openpilot.system.ui.lib.application import gui_app, FontWeight, MousePos
from openpilot.system.ui.widgets import Widget
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


class ESimProfileButton(BigButton):
  LABEL_PADDING = 98
  LABEL_WIDTH = 402 - 98 - 28
  SUB_LABEL_WIDTH = 402 - BigButton.LABEL_HORIZONTAL_PADDING * 2

  def __init__(self, profile: Profile, esim_manager: ESimManager):
    display_name = profile.nickname or profile.provider or profile.iccid[:12]
    super().__init__(display_name, scroll=True)

    self._profile = profile
    self._esim_manager = esim_manager
    self._deleting = False

    self._cell_full_txt = gui_app.texture("icons_mici/settings/network/cell_strength_full.png", 48, 36)
    self._cell_none_txt = gui_app.texture("icons_mici/settings/network/cell_strength_none.png", 48, 36)
    self._check_txt = gui_app.texture("icons_mici/setup/driver_monitoring/dm_check.png", 32, 32)

    self._delete_btn = DeleteButton(self._on_delete)

  @property
  def profile(self) -> Profile:
    return self._profile

  def update_profile(self, profile: Profile):
    self._profile = profile
    self._deleting = False
    display_name = profile.nickname or profile.provider or profile.iccid[:12]
    self.set_text(display_name)

  @property
  def _show_delete_btn(self) -> bool:
    if self._deleting or self._profile.enabled:
      return False
    return not self._esim_manager.is_comma_profile(self._profile.iccid)

  def _on_delete(self):
    if self._deleting:
      return
    self._deleting = True
    self._esim_manager.delete_profile(self._profile.iccid)

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

    # Cell icon
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

    if self._esim_manager.busy or self._deleting:
      self.set_enabled(False)
      self._sub_label.set_color(rl.Color(255, 255, 255, int(255 * 0.585)))
      self._sub_label.set_font_weight(FontWeight.ROMAN)

      if self._deleting:
        self.set_value("deleting...")
      elif self._esim_manager.busy:
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
  def __init__(self, esim_manager: ESimManager):
    super().__init__()

    self._esim_manager = esim_manager
    self._add_profile_btn = BigButton("add profile", "coming soon")
    self._add_profile_btn.set_enabled(False)

    self._esim_manager.add_callbacks(
      profiles_updated=self._on_profiles_updated,
    )

  def show_event(self):
    super().show_event()
    self._esim_manager.refresh_profiles()

  def _on_profiles_updated(self, profiles: list[Profile]):
    existing = {btn.profile.iccid: btn for btn in self._scroller.items if isinstance(btn, ESimProfileButton)}

    current_iccids = {p.iccid for p in profiles}

    # Update existing and add new
    for profile in profiles:
      if profile.iccid in existing:
        existing[profile.iccid].update_profile(profile)
      else:
        btn = ESimProfileButton(profile, self._esim_manager)
        btn.set_click_callback(lambda iccid=profile.iccid: self._on_profile_clicked(iccid))
        self._scroller.add_widget(btn)

    # Remove deleted profiles
    self._scroller.items[:] = [
      btn for btn in self._scroller.items
      if not isinstance(btn, ESimProfileButton) or btn.profile.iccid in current_iccids
    ]

    # Sort: active first
    profile_btns = [btn for btn in self._scroller.items if isinstance(btn, ESimProfileButton)]
    other_btns = [btn for btn in self._scroller.items if not isinstance(btn, ESimProfileButton)]
    profile_btns.sort(key=lambda btn: (not btn.profile.enabled, btn.profile.nickname or btn.profile.provider))
    self._scroller.items[:] = profile_btns + other_btns

    # Keep add button at the end
    if self._add_profile_btn in self._scroller.items:
      self._scroller.items.remove(self._add_profile_btn)
    self._scroller.add_widget(self._add_profile_btn)

  def _on_profile_clicked(self, iccid: str):
    profile = next((p for p in self._esim_manager.profiles if p.iccid == iccid), None)
    if profile is None:
      return

    if profile.enabled:
      # Edit nickname
      current_name = profile.nickname or ""
      dlg = BigInputDialog("enter nickname...", current_name, minimum_length=0,
                           confirm_callback=lambda name: self._esim_manager.nickname_profile(iccid, name))
      gui_app.push_widget(dlg)
    else:
      # Switch to profile
      cell_icon = gui_app.texture("icons_mici/settings/network/cell_strength_full.png", 54, 40)
      dlg = BigConfirmationDialog("slide to switch", cell_icon,
                                  lambda: self._esim_manager.switch_profile(iccid))
      gui_app.push_widget(dlg)
