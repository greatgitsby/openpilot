import pyray as rl
from dataclasses import dataclass
from enum import IntEnum
from collections.abc import Callable

from openpilot.system.ui.widgets.label import UnifiedLabel
from openpilot.system.ui.widgets.scroller import Scroller
from openpilot.system.ui.widgets import Widget, NavWidget
from openpilot.system.ui.lib.application import gui_app, FontWeight, FONT_SCALE
from openpilot.system.ui.lib.wrap_text import wrap_text
from openpilot.system.ui.lib.scroll_panel2 import GuiScrollPanel2
from openpilot.selfdrive.ui.mici.widgets.button import BigButton
from openpilot.selfdrive.ui.mici.widgets.dialog import BigMultiOptionDialog, BigDialogOptionButton


@dataclass
class EsimProfile:
  iccid: str          # e.g., "8901234567890123456"
  name: str           # e.g., "AT&T Business"
  provider: str       # e.g., "AT&T"
  is_active: bool     # True if currently active profile


class EsimSubPanelType(IntEnum):
  NONE = 0
  PROFILES = 1
  NEW_PROFILE = 2


def _generate_placeholder_profiles() -> list[EsimProfile]:
  """Generate placeholder eSIM profiles for demo purposes"""
  return [
    EsimProfile(
      iccid="8901234567890123456",
      name="AT&T Business",
      provider="AT&T",
      is_active=True
    ),
    EsimProfile(
      iccid="8901234567890123457",
      name="T-Mobile Personal",
      provider="T-Mobile",
      is_active=False
    ),
    EsimProfile(
      iccid="8901234567890123458",
      name="Verizon Travel",
      provider="Verizon",
      is_active=False
    ),
  ]


class EsimProfileButton(BigDialogOptionButton):
  """List item widget for displaying eSIM profile in scroller"""
  LEFT_MARGIN = 20

  def __init__(self, profile: EsimProfile):
    super().__init__(profile.name)
    self.set_rect(rl.Rectangle(0, 0, gui_app.width, self.HEIGHT))

    self._profile = profile
    self._selected_txt = gui_app.texture("icons_mici/settings/network/new/wifi_selected.png", 48, 96)

  def set_current_profile(self, profile: EsimProfile):
    self._profile = profile

  def _render(self, _):
    # Show active indicator if this is the active profile
    if self._profile.is_active:
      selected_x = int(self._rect.x - self._selected_txt.width / 2)
      selected_y = int(self._rect.y + (self._rect.height - self._selected_txt.height) / 2)
      rl.draw_texture(self._selected_txt, selected_x, selected_y, rl.WHITE)

    # Set label styling based on selection
    if self._selected:
      self._label.set_font_size(self.SELECTED_HEIGHT)
      self._label.set_color(rl.Color(255, 255, 255, int(255 * 0.9)))
      self._label.set_font_weight(FontWeight.DISPLAY)
    else:
      self._label.set_font_size(self.HEIGHT)
      self._label.set_color(rl.Color(255, 255, 255, int(255 * 0.58)))
      self._label.set_font_weight(FontWeight.DISPLAY_REGULAR)

    # Render profile name
    label_offset = self.LEFT_MARGIN + 20
    label_rect = rl.Rectangle(
      self._rect.x + label_offset,
      self._rect.y,
      self._rect.width - label_offset,
      self._rect.height
    )
    self._label.set_text(self._profile.name)
    self._label.render(label_rect)


class EsimProfileDetailView(NavWidget):
  """Modal overlay showing detailed eSIM profile information"""

  def __init__(self):
    super().__init__()
    self.set_rect(rl.Rectangle(0, 0, gui_app.width, gui_app.height))

    self._profile: EsimProfile | None = None
    self._scroll_panel = GuiScrollPanel2(horizontal=False)

    # Back button closes modal
    self.set_back_callback(lambda: gui_app.set_modal_overlay(None))

  def show_event(self):
    super().show_event()
    self._scroll_panel.set_offset(0)

  def set_current_profile(self, profile: EsimProfile):
    self._profile = profile

  def _draw_wrapped_text(self, x, y, width, text, font, font_size, color):
    """Helper to draw wrapped text and return new y position"""
    wrapped = wrap_text(font, text, font_size, width)
    for line in wrapped:
      rl.draw_text_ex(font, line, rl.Vector2(x, y), font_size, 0, color)
      y += int(font_size * FONT_SCALE)
    return y

  def _measure_content_height(self, rect: rl.Rectangle) -> int:
    """Measure total content height for scrolling"""
    if self._profile is None:
      return 0

    w = int(rect.width - 80)
    y = 40

    # Profile name
    name_lines = wrap_text(gui_app.font(FontWeight.DISPLAY), self._profile.name, 64, w)
    y += int(len(name_lines) * 64 * FONT_SCALE) + 30

    # Provider
    provider_text = f"Provider: {self._profile.provider}"
    provider_lines = wrap_text(gui_app.font(FontWeight.ROMAN), provider_text, 48, w)
    y += int(len(provider_lines) * 48 * FONT_SCALE) + 20

    # ICCID
    iccid_text = f"ICCID: {self._profile.iccid}"
    iccid_lines = wrap_text(gui_app.font(FontWeight.ROMAN), iccid_text, 36, w)
    y += int(len(iccid_lines) * 36 * FONT_SCALE) + 20

    # Status
    status_text = f"Status: {'Active' if self._profile.is_active else 'Inactive'}"
    status_lines = wrap_text(gui_app.font(FontWeight.MEDIUM), status_text, 36, w)
    y += int(len(status_lines) * 36 * FONT_SCALE) + 20

    # Bottom padding
    y += 40
    return y

  def _render(self, rect: rl.Rectangle):
    if self._profile is None:
      return -1

    # Compute total content height for scrolling
    content_height = self._measure_content_height(rect)
    scroll_offset = round(self._scroll_panel.update(rect, content_height))

    # Start drawing with offset
    x = int(rect.x + 40)
    y = int(rect.y + 40 + scroll_offset)
    w = int(rect.width - 80)

    # Profile name (large, bold)
    y = self._draw_wrapped_text(x, y, w, self._profile.name,
                                gui_app.font(FontWeight.DISPLAY), 64,
                                rl.Color(255, 255, 255, int(255 * 0.9)))
    y += 30

    # Provider
    provider_text = f"Provider: {self._profile.provider}"
    y = self._draw_wrapped_text(x, y, w, provider_text,
                                gui_app.font(FontWeight.ROMAN), 48,
                                rl.Color(255, 255, 255, int(255 * 0.65)))
    y += 20

    # ICCID
    iccid_text = f"ICCID: {self._profile.iccid}"
    y = self._draw_wrapped_text(x, y, w, iccid_text,
                                gui_app.font(FontWeight.ROMAN), 36,
                                rl.Color(255, 255, 255, int(255 * 0.65)))
    y += 20

    # Status
    status_text = f"Status: {'Active' if self._profile.is_active else 'Inactive'}"
    y = self._draw_wrapped_text(x, y, w, status_text,
                                gui_app.font(FontWeight.MEDIUM), 36,
                                rl.Color(255, 255, 255, int(255 * 0.9)))

    return -1


class EsimNewProfileView(NavWidget):
  """Placeholder view for adding new eSIM profiles"""

  def __init__(self):
    super().__init__()
    self._todo_label = UnifiedLabel(
      "TODO", 64, FontWeight.DISPLAY, rl.Color(255, 255, 255, int(255 * 0.9)),
      alignment=rl.GuiTextAlignment.TEXT_ALIGN_CENTER,
      alignment_vertical=rl.GuiTextAlignmentVertical.TEXT_ALIGN_MIDDLE
    )

  def _render(self, rect: rl.Rectangle):
    # Render centered "TODO" text
    self._todo_label.render(rect)


class EsimProfilesView(BigMultiOptionDialog):
  """Scrollable list view of eSIM profiles"""

  def __init__(self, profiles: list[EsimProfile]):
    super().__init__([], None, None, right_btn_callback=None)

    self._profiles: dict[str, EsimProfile] = {}  # Map profile name to profile
    self._profile_detail_view = EsimProfileDetailView()

    # Populate profiles
    for profile in profiles:
      self._profiles[profile.name] = profile
      profile_button = EsimProfileButton(profile)
      self._scroller.add_widget(profile_button)

  def _on_option_selected(self, option: str):
    """Handle profile selection - open detail modal"""
    super()._on_option_selected(option)

    if option in self._profiles:
      self._profile_detail_view.set_current_profile(self._profiles[option])
      self._profile_detail_view.show_event()
      gui_app.set_modal_overlay(self._profile_detail_view)


class EsimUIMici(NavWidget):
  """Main eSIM UI controller with profiles and new profile views"""

  def __init__(self, back_callback: Callable):
    super().__init__()

    self._current_subpanel = EsimSubPanelType.NONE
    self.set_back_enabled(lambda: self._current_subpanel == EsimSubPanelType.NONE)

    # Generate placeholder data
    placeholder_profiles = _generate_placeholder_profiles()

    # Create sub-views
    self._profiles_view = EsimProfilesView(placeholder_profiles)
    self._new_profile_view = EsimNewProfileView()

    # Create navigation buttons in a scroller (like network panel)
    profiles_btn = BigButton("profiles")
    profiles_btn.set_click_callback(lambda: self._switch_to_subpanel(EsimSubPanelType.PROFILES))

    new_profile_btn = BigButton("new")
    new_profile_btn.set_click_callback(lambda: self._switch_to_subpanel(EsimSubPanelType.NEW_PROFILE))

    # Create scroller with buttons
    self._scroller = Scroller([
      profiles_btn,
      new_profile_btn,
    ], snap_items=False)

    # Set up back navigation
    self.set_back_callback(back_callback)

  def show_event(self):
    super().show_event()
    self._current_subpanel = EsimSubPanelType.NONE
    self._scroller.show_event()

  def hide_event(self):
    super().hide_event()
    self._profiles_view.hide_event()

  def _switch_to_subpanel(self, subpanel_type: EsimSubPanelType):
    """Switch between profiles and new profile views"""
    if subpanel_type == EsimSubPanelType.PROFILES:
      self._profiles_view.show_event()
      self._profiles_view.set_back_callback(lambda: self._switch_to_subpanel(EsimSubPanelType.NONE))
    elif subpanel_type == EsimSubPanelType.NEW_PROFILE:
      self._new_profile_view.show_event()
      self._new_profile_view.set_back_callback(lambda: self._switch_to_subpanel(EsimSubPanelType.NONE))
    self._current_subpanel = subpanel_type

  def _render(self, rect: rl.Rectangle):
    if self._current_subpanel == EsimSubPanelType.PROFILES:
      self._profiles_view.render(rect)
    elif self._current_subpanel == EsimSubPanelType.NEW_PROFILE:
      self._new_profile_view.render(rect)
    else:
      self._scroller.render(rect)
