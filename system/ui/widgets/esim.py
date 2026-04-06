from enum import IntEnum
from functools import partial

import pyray as rl

from openpilot.system.ui.lib.application import gui_app, FontWeight
from openpilot.system.ui.lib.cellular_manager import CellularManager
from openpilot.system.ui.lib.scroll_panel import GuiScrollPanel
from openpilot.system.hardware.base import Profile
from openpilot.system.ui.widgets import DialogResult, Widget
from openpilot.system.ui.widgets.button import ButtonStyle, Button
from openpilot.system.ui.widgets.confirm_dialog import ConfirmDialog, alert_dialog
from openpilot.system.ui.widgets.keyboard import Keyboard
from openpilot.system.ui.widgets.label import gui_label

ITEM_HEIGHT = 160
ICON_SIZE = 50
COMMA_ICON_SIZE = 40
MAX_NICKNAME_LENGTH = 64


class UIState(IntEnum):
  IDLE = 0
  SWITCHING = 1
  DELETING = 2


def _profile_display_name(profile: Profile) -> str:
  return profile.nickname or profile.provider or profile.iccid[:12]


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
    self._rename_buttons: dict[str, Button] = {}
    self._active_button = Button("Active", lambda: None, font_size=45, button_style=ButtonStyle.NORMAL)
    self._active_button.set_enabled(False)

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
    self._profiles = profiles
    self._profile_buttons.clear()
    self._forget_buttons.clear()
    self._rename_buttons.clear()

    for p in self._profiles:
      is_comma = self._cellular_manager.is_comma_profile(p.iccid)
      display = "comma prime" if is_comma else _profile_display_name(p)
      self._profile_buttons[p.iccid] = Button(display, partial(self._on_profile_clicked, p.iccid), font_size=55,
                                                text_alignment=rl.GuiTextAlignment.TEXT_ALIGN_LEFT,
                                                button_style=ButtonStyle.TRANSPARENT_WHITE_TEXT)
      self._profile_buttons[p.iccid].set_touch_valid_callback(lambda: self.scroll_panel.is_touch_valid())

      if not is_comma:
        self._rename_buttons[p.iccid] = Button("Rename", partial(self._on_rename_clicked, p.iccid),
                                                button_style=ButtonStyle.LIST_ACTION, font_size=45)
        self._rename_buttons[p.iccid].set_touch_valid_callback(lambda: self.scroll_panel.is_touch_valid())

      if not p.enabled and not is_comma:
        self._forget_buttons[p.iccid] = Button("Forget", partial(self._on_forget_clicked, p.iccid),
                                                button_style=ButtonStyle.FORGET_WIFI, font_size=45)
        self._forget_buttons[p.iccid].set_touch_valid_callback(lambda: self.scroll_panel.is_touch_valid())

    if self.state == UIState.SWITCHING or self.state == UIState.DELETING:
      self.state = UIState.IDLE
      self._state_iccid = None

  def _on_error(self, error: str):
    self.state = UIState.IDLE
    self._state_iccid = None
    gui_app.push_widget(alert_dialog(error))

  def _render(self, rect: rl.Rectangle):
    if not self._profiles:
      gui_label(rect, "Loading eSIM profiles...", 72, alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
      return

    total_items = len(self._profiles)
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

    rl.end_scissor_mode()

  def _draw_profile_item(self, rect: rl.Rectangle, profile: Profile):
    btn_width = 200
    rename_btn_width = 240
    spacing = 50
    is_comma = self._cellular_manager.is_comma_profile(profile.iccid)

    # Draw comma icon for comma profiles
    icon_offset = 0
    if is_comma:
      icon = gui_app.texture("icons_mici/settings/comma_icon.png", COMMA_ICON_SIZE, COMMA_ICON_SIZE)
      icon_x = rect.x + 20
      icon_y = rect.y + (ITEM_HEIGHT - COMMA_ICON_SIZE) / 2
      rl.draw_texture_v(icon, rl.Vector2(icon_x, icon_y), rl.WHITE)
      icon_offset = COMMA_ICON_SIZE + 30

    ssid_rect = rl.Rectangle(rect.x + icon_offset, rect.y, rect.width - btn_width * 2 - icon_offset, ITEM_HEIGHT)

    status_text = ""
    if self.state == UIState.SWITCHING and self._state_iccid == profile.iccid:
      self._profile_buttons[profile.iccid].set_enabled(False)
      status_text = "SWITCHING..."
    elif self.state == UIState.DELETING and self._state_iccid == profile.iccid:
      self._profile_buttons[profile.iccid].set_enabled(False)
      status_text = "DELETING..."
    elif profile.enabled:
      pass
    else:
      self._profile_buttons[profile.iccid].set_enabled(True)

    self._profile_buttons[profile.iccid].render(ssid_rect)

    if status_text:
      status_rect = rl.Rectangle(rect.x + rect.width - 410 - spacing, rect.y, 410, ITEM_HEIGHT)
      gui_label(status_rect, status_text, font_size=48, alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER)
    elif profile.enabled:
      btn_x = rect.x + rect.width - btn_width - spacing
      active_rect = rl.Rectangle(btn_x, rect.y + (ITEM_HEIGHT - 80) / 2, btn_width, 80)
      self._active_button.render(active_rect)
      if profile.iccid in self._rename_buttons:
        rename_rect = rl.Rectangle(btn_x - rename_btn_width - 10, rect.y + (ITEM_HEIGHT - 80) / 2, rename_btn_width, 80)
        self._rename_buttons[profile.iccid].render(rename_rect)
    elif profile.iccid in self._forget_buttons:
      btn_x = rect.x + rect.width - btn_width - spacing
      forget_rect = rl.Rectangle(btn_x, rect.y + (ITEM_HEIGHT - 80) / 2, btn_width, 80)
      self._forget_buttons[profile.iccid].render(forget_rect)
      if profile.iccid in self._rename_buttons:
        rename_rect = rl.Rectangle(btn_x - rename_btn_width - 10, rect.y + (ITEM_HEIGHT - 80) / 2, rename_btn_width, 80)
        self._rename_buttons[profile.iccid].render(rename_rect)

  def _on_profile_clicked(self, iccid: str):
    if self.state != UIState.IDLE:
      return
    profile = next((p for p in self._profiles if p.iccid == iccid), None)
    if profile is None or profile.enabled:
      return

    self.state = UIState.SWITCHING
    self._state_iccid = iccid
    self._cellular_manager.switch_profile(iccid)

  def _on_rename_clicked(self, iccid: str):
    if self.state != UIState.IDLE:
      return
    profile = next((p for p in self._profiles if p.iccid == iccid), None)
    if profile is None:
      return

    current_name = profile.nickname or ""
    self.keyboard.reset(min_text_size=0)
    self.keyboard.set_title("Enter nickname", f"for \"{_profile_display_name(profile)}\"")
    self.keyboard.set_text(current_name)
    self.keyboard.set_callback(lambda result: self._on_nickname_entered(iccid, result))
    gui_app.push_widget(self.keyboard)

  def _on_nickname_entered(self, iccid: str, result: DialogResult):
    if result == DialogResult.CONFIRM:
      nickname = self.keyboard.text.strip()
      self._cellular_manager.nickname_profile(iccid, nickname)

  def _on_forget_clicked(self, iccid: str):
    if self.state != UIState.IDLE:
      return
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
