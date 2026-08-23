from __future__ import annotations

import os
import pyray as rl
from datetime import datetime, timedelta

from openpilot.common.basedir import BASEDIR
from openpilot.selfdrive.ui.ui_state import ui_state
from openpilot.system.ui.lib.application import gui_app, FontWeight
from openpilot.system.ui.lib.multilang import tr
from openpilot.system.ui.lib.text_measure import measure_text_cached
from openpilot.system.ui.lib.wrap_text import wrap_text
from openpilot.system.ui.widgets import Widget

ICON_DIR = "navigation"
ICON_PATH = f"{BASEDIR}/openpilot/selfdrive/assets/{ICON_DIR}"
FALLBACK_ICON = "direction_invalid"

CHIME_PATH = f"{BASEDIR}/openpilot/selfdrive/assets/sounds/warning.wav"

METER_TO_FOOT = 3.28084
METER_TO_MILE = 0.000621371

# navLaneAdvice enumerant name -> displayed text
LANE_ADVICE_TEXT = {
  "moveLeft": "Move left",
  "moveRight": "Move right",
}


class NavColors:
  BG = rl.Color(0, 0, 0, 166)
  WHITE = rl.WHITE
  DIM = rl.Color(255, 255, 255, 200)
  ADVICE = rl.Color(128, 216, 166, 255)


COLORS = NavColors()


def _icon_name(maneuver_type: str, modifier: str) -> str:
  base = "direction_" + maneuver_type.strip().lower().replace(" ", "_")
  mod = modifier.strip().lower().replace(" ", "_")
  return f"{base}_{mod}" if mod else base


class NavChime:
  """Plays the prompt chime in the UI process. Falls back to silence if the audio device is unavailable."""

  def __init__(self):
    self._sound: rl.Sound | None = None
    self._failed = False

  def play(self) -> None:
    if self._failed:
      return

    try:
      if self._sound is None:
        if not rl.is_audio_device_ready():
          rl.init_audio_device()
        if not rl.is_audio_device_ready():
          self._failed = True
          return
        self._sound = rl.load_sound(CHIME_PATH)
      rl.play_sound(self._sound)
    except Exception:
      self._failed = True


class NavRenderer(Widget):
  PANEL_WIDTH = 760
  PADDING = 30
  ICON_SIZE = 120

  def __init__(self, scale: float = 1.0):
    super().__init__()
    self._scale = scale

    self._font_bold: rl.Font = gui_app.font(FontWeight.BOLD)
    self._font_medium: rl.Font = gui_app.font(FontWeight.MEDIUM)

    self._icon_size = round(self.ICON_SIZE * scale)
    self._padding = round(self.PADDING * scale)
    self._panel_width = round(self.PANEL_WIDTH * scale)
    self._distance_size = round(70 * scale)
    self._primary_size = round(48 * scale)
    self._eta_size = round(36 * scale)

    self._available_icons = {f[:-4] for f in os.listdir(ICON_PATH) if f.endswith(".png")}
    self._textures: dict[str, rl.Texture] = {}

    self._chime = NavChime()
    self._lane_advice_prev = "none"

    self._valid = False
    self._icon: rl.Texture | None = None
    self._distance_text = ""
    self._primary_lines: list[str] = []
    self._eta_text = ""
    self._advice_text = ""

    self.set_visible(lambda: self._valid)

  def _texture(self, name: str) -> rl.Texture | None:
    if name not in self._available_icons:
      return None
    if name not in self._textures:
      self._textures[name] = gui_app.texture(f"{ICON_DIR}/{name}.png", self._icon_size, self._icon_size)
    return self._textures[name]

  def _lookup_icon(self, maneuver_type: str, modifier: str) -> rl.Texture | None:
    for name in (_icon_name(maneuver_type, modifier), _icon_name(maneuver_type, ""), FALLBACK_ICON):
      texture = self._texture(name)
      if texture is not None:
        return texture
    return None

  def _format_distance(self, meters: float) -> str:
    if ui_state.is_metric:
      if meters < 1000:
        return f"{max(0, round(meters / 10) * 10)} " + tr("m")
      return f"{meters / 1000:.1f} " + tr("km")

    feet = meters * METER_TO_FOOT
    if feet < 1000:
      return f"{max(0, round(feet / 10) * 10)} " + tr("ft")
    return f"{meters * METER_TO_MILE:.1f} " + tr("mi")

  def _format_remaining(self, instruction) -> str:
    minutes = max(0, round(instruction.timeRemaining / 60))
    eta = datetime.now() + timedelta(seconds=instruction.timeRemaining)
    return f"{minutes} " + tr("min") + f"  {self._format_distance(instruction.distanceRemaining)}  {eta.strftime('%H:%M')}"

  def _lane_advice(self) -> str:
    try:
      return str(ui_state.sm['modelV2'].meta.navLaneAdvice)
    except Exception:
      return "none"

  def _update_state(self) -> None:
    sm = ui_state.sm
    self._valid = (ui_state.started and sm.valid['navInstruction'] and sm.alive['navInstruction'] and
                   sm.recv_frame['navInstruction'] > ui_state.started_frame)

    advice = self._lane_advice()
    if advice != self._lane_advice_prev:
      if advice in LANE_ADVICE_TEXT and self._valid:
        self._chime.play()
      self._lane_advice_prev = advice
    self._advice_text = tr(LANE_ADVICE_TEXT[advice]) if advice in LANE_ADVICE_TEXT else ""

    if not self._valid:
      return

    instruction = sm['navInstruction']
    self._icon = self._lookup_icon(instruction.maneuverType, instruction.maneuverModifier)
    self._distance_text = self._format_distance(instruction.maneuverDistance)
    self._eta_text = self._format_remaining(instruction)

    text_width = self._panel_width - 3 * self._padding - self._icon_size
    self._primary_lines = wrap_text(self._font_medium, instruction.maneuverPrimaryText, self._primary_size, text_width)[:2]

  def _render(self, rect: rl.Rectangle) -> None:
    line_height = self._primary_size + round(8 * self._scale)
    body_height = max(self._icon_size, self._distance_size + len(self._primary_lines) * line_height)
    panel_height = body_height + 2 * self._padding + self._eta_size + round(10 * self._scale)
    if self._advice_text:
      panel_height += self._primary_size + round(10 * self._scale)

    x = rect.x + self._padding
    y = rect.y + self._padding
    panel = rl.Rectangle(x, y, self._panel_width, panel_height)
    rl.draw_rectangle_rounded(panel, 0.15, 10, COLORS.BG)

    text_x = x + self._padding
    if self._icon is not None:
      rl.draw_texture_ex(self._icon, rl.Vector2(x + self._padding, y + self._padding), 0, 1.0, rl.WHITE)
      text_x += self._icon_size + self._padding

    text_y = y + self._padding
    rl.draw_text_ex(self._font_bold, self._distance_text, rl.Vector2(text_x, text_y), self._distance_size, 0, COLORS.WHITE)
    text_y += self._distance_size

    for line in self._primary_lines:
      rl.draw_text_ex(self._font_medium, line, rl.Vector2(text_x, text_y), self._primary_size, 0, COLORS.WHITE)
      text_y += line_height

    if self._advice_text:
      advice_width = measure_text_cached(self._font_bold, self._advice_text, self._primary_size).x
      rl.draw_text_ex(self._font_bold, self._advice_text,
                      rl.Vector2(x + (self._panel_width - advice_width) / 2, text_y), self._primary_size, 0, COLORS.ADVICE)
      text_y += self._primary_size + round(10 * self._scale)

    eta_y = y + panel_height - self._padding - self._eta_size
    rl.draw_text_ex(self._font_medium, self._eta_text, rl.Vector2(x + self._padding, eta_y), self._eta_size, 0, COLORS.DIM)
