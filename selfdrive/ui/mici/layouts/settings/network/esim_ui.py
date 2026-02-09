import pyray as rl
from collections.abc import Callable

from openpilot.system.hardware.base import Profile
from openpilot.selfdrive.ui.mici.widgets.dialog import BigMultiOptionDialog, BigDialogOptionButton
from openpilot.system.ui.lib.application import gui_app, FontWeight


class EsimItem(BigDialogOptionButton):
  def __init__(self, profile: Profile):
    super().__init__(profile.nickname)

    self.set_rect(rl.Rectangle(0, 0, gui_app.width, self.HEIGHT))

    self._selected_txt = gui_app.texture("icons_mici/settings/network/new/wifi_selected.png", 48, 96)
    self._profile = profile

  def _render(self, _):
    if self._profile.enabled:
      selected_x = int(self._rect.x - self._selected_txt.width / 2)
      selected_y = int(self._rect.y + (self._rect.height - self._selected_txt.height) / 2)
      rl.draw_texture(self._selected_txt, selected_x, selected_y, rl.WHITE)

    if self._selected:
      self._label.set_font_size(self.SELECTED_HEIGHT)
      self._label.set_color(rl.Color(255, 255, 255, int(255 * 0.9)))
      self._label.set_font_weight(FontWeight.DISPLAY)
    else:
      self._label.set_font_size(self.HEIGHT)
      self._label.set_color(rl.Color(255, 255, 255, int(255 * 0.58)))
      self._label.set_font_weight(FontWeight.DISPLAY_REGULAR)

    self._label.render(self._rect)


class EsimUIMici(BigMultiOptionDialog):
  def __init__(self, back_callback: Callable):
    super().__init__([], None, None, right_btn_callback=None)

    self.set_back_callback(back_callback)

    self._add_new_btn = BigDialogOptionButton("add new sim")
    self._add_new_btn.set_rect(rl.Rectangle(0, 0, gui_app.width, self._add_new_btn.HEIGHT))
    self._scroller.add_widget(self._add_new_btn)

    self._profiles = [
      Profile(iccid="8985235000000000001", nickname="comma connect", enabled=True, provider="comma"),
      Profile(iccid="8901234567890123456", nickname="T-Mobile", enabled=False, provider="T-Mobile US"),
      Profile(iccid="8907654321098765432", nickname="Travel eSIM", enabled=False, provider="Airalo"),
    ]

    for profile in self._profiles:
      self._scroller.add_widget(EsimItem(profile))

  def _on_option_selected(self, option: str):
    super()._on_option_selected(option)

    if option == "add new sim":
      return

    for profile in self._profiles:
      profile.enabled = profile.nickname == option
