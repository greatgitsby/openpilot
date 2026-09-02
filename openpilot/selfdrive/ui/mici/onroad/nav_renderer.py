import os
import pyray as rl

from openpilot.common.basedir import BASEDIR
from openpilot.common.filter_simple import FirstOrderFilter
from openpilot.selfdrive.ui.ui_state import ui_state, UIStatus
from openpilot.selfdrive.ui.mici.onroad.torque_bar import TorqueBar
from openpilot.system.ui.lib.application import gui_app, FontWeight
from openpilot.system.ui.lib.multilang import tr
from openpilot.system.ui.lib.text_measure import measure_text_cached
from openpilot.system.ui.widgets import Widget

ICON_DIR = "navigation"
ICON_PATH = f"{BASEDIR}/openpilot/selfdrive/assets/{ICON_DIR}"
FALLBACK_ICON = "direction_invalid"

METER_TO_FOOT = 3.28084
METER_TO_MILE = 0.000621371

CARD_WIDTH = 240
ICON_SIZE = 120
GHOST_ALPHA = 0.08  # nav content ghosts to this under alerts

ADVICE_COLOR = rl.Color(128, 216, 166, 255)
STREET_COLOR = rl.Color(185, 185, 192, 255)
UNIT_COLOR = rl.Color(154, 154, 162, 255)
CARD_BG = rl.Color(16, 16, 20, 255)
CARD_BORDER = rl.Color(34, 34, 34, 255)

# navLaneAdvice enumerant name -> displayed text
LANE_ADVICE_TEXT = {
  "moveLeft": "Move left",
  "moveRight": "Move right",
}


def _icon_name(maneuver_type: str, modifier: str) -> str:
  base = "direction_" + maneuver_type.strip().lower().replace(" ", "_")
  mod = modifier.strip().lower().replace(" ", "_")
  return f"{base}_{mod}" if mod else base


def _lerp(a: float, b: float, f: float) -> float:
  return a + (b - a) * min(1.0, max(0.0, f))


class FlatTorqueBar(TorqueBar):
  """Flat bottom strip variant: center-out fill, grows 8->27px as |torque| goes 0.5->1."""

  def __init__(self):
    super().__init__()
    self.alpha = 1.0

  def _blend(self, hot: tuple[int, int, int], heat: float, alpha: float) -> rl.Color:
    r, g, b = (round(_lerp(255, c, heat)) for c in hot)
    return rl.Color(r, g, b, int(255 * alpha))

  def _render(self, rect: rl.Rectangle) -> None:
    self._torque_line_alpha_filter.update(ui_state.status != UIStatus.DISENGAGED)
    alpha = self.alpha * self._torque_line_alpha_filter.x
    if alpha < 0.02:
      return

    t = self._torque_filter.x
    abs_t = abs(t)
    height = round(_lerp(8, 27, (abs_t - 0.5) * 2))
    gray = round(255 * _lerp(0.12, 0.3, (abs_t - 0.5) * 2))
    y = int(rect.y + rect.height - height)
    rl.draw_rectangle(int(rect.x), y, int(rect.width), height, rl.Color(gray, gray, gray, int(255 * alpha)))

    heat = max(0.0, abs_t - 0.75) * 4
    start = self._blend((255, 200, 0), heat, 0.9 * alpha)
    end = self._blend((255, 115, 0), heat, alpha)
    if ui_state.status != UIStatus.ENGAGED:
      start = end = rl.Color(255, 255, 255, int(255 * 0.35 * alpha))

    cx = rect.x + rect.width / 2
    w = abs_t * rect.width / 2
    fx = int(cx) if t >= 0 else int(cx - w)
    left, right = (start, end) if t >= 0 else (end, start)
    rl.draw_rectangle_gradient_h(fx, y, int(w), height, left, right)


class NavRenderer(Widget):
  """Nav-only onroad screen: maneuver card, trip panel, flat torque strip."""

  def __init__(self):
    super().__init__()
    self._font_bold = gui_app.font(FontWeight.DISPLAY)
    self._font_medium = gui_app.font(FontWeight.MEDIUM)

    self._available_icons = {f[:-4] for f in os.listdir(ICON_PATH) if f.endswith(".png")}
    self._textures: dict[str, rl.Texture] = {}

    self._torque_bar = FlatTorqueBar()
    self._nav_alpha = FirstOrderFilter(1.0, 0.08, 1 / gui_app.target_fps)
    self._ball_alpha = FirstOrderFilter(1.0, 0.1, 1 / gui_app.target_fps)
    self._alert_showing = False

    self._icon: rl.Texture | None = None
    self._distance_text = ""
    self._street_text = ""
    self._trip_rows: list[tuple[str, str]] = []
    self._advice_text = ""

  @property
  def active(self) -> bool:
    sm = ui_state.sm
    return (ui_state.navigation_enabled and ui_state.nav_destination_set and
            sm.valid['navInstruction'] and sm.alive['navInstruction'] and
            sm.recv_frame['navInstruction'] > ui_state.started_frame)

  @property
  def ball_alpha(self) -> float:
    return self._ball_alpha.x

  def set_alert_showing(self, showing: bool) -> None:
    self._alert_showing = showing

  def _texture(self, name: str) -> rl.Texture | None:
    if name not in self._available_icons:
      return None
    if name not in self._textures:
      self._textures[name] = gui_app.texture(f"{ICON_DIR}/{name}.png", ICON_SIZE, ICON_SIZE)
    return self._textures[name]

  def _lookup_icon(self, maneuver_type: str, modifier: str) -> rl.Texture | None:
    for name in (_icon_name(maneuver_type, modifier), _icon_name(maneuver_type, ""), FALLBACK_ICON):
      texture = self._texture(name)
      if texture is not None:
        return texture
    return None

  def _format_distance(self, meters: float) -> tuple[str, str]:
    meters = max(0.0, meters)
    if ui_state.is_metric:
      if meters < 1000:
        return str(round(meters / 10) * 10), tr("m")
      return f"{meters / 1000:.1f}", tr("km")
    feet = meters * METER_TO_FOOT
    if feet < 1000:
      return str(round(feet / 10) * 10), tr("ft")
    return f"{meters * METER_TO_MILE:.1f}", tr("mi")

  def _lane_advice(self) -> str:
    try:
      return str(ui_state.sm['modelV2'].meta.navLaneAdvice)
    except Exception:
      return "none"

  def _update_state(self) -> None:
    self._nav_alpha.update(GHOST_ALPHA if self._alert_showing else 1.0)
    self._ball_alpha.update(0.0 if self._alert_showing else 1.0)

    instruction = ui_state.sm['navInstruction']
    self._icon = self._lookup_icon(instruction.maneuverType, instruction.maneuverModifier)
    self._distance_text = " ".join(self._format_distance(instruction.maneuverDistance))
    self._street_text = instruction.maneuverPrimaryText
    self._trip_rows = [(str(max(0, round(instruction.timeRemaining / 60))), tr("min")),
                       self._format_distance(instruction.distanceRemaining)]

    advice = self._lane_advice()
    self._advice_text = tr(LANE_ADVICE_TEXT[advice]) if advice in LANE_ADVICE_TEXT else ""

  def _render(self, rect: rl.Rectangle) -> None:
    alpha = self._nav_alpha.x
    self._draw_maneuver_card(rect, alpha)
    self._draw_trip(rect, alpha)
    self._torque_bar.alpha = alpha
    self._torque_bar.render(rect)

  def _draw_maneuver_card(self, rect: rl.Rectangle, alpha: float) -> None:
    a8 = int(255 * alpha)
    rl.draw_rectangle(int(rect.x), int(rect.y), CARD_WIDTH, int(rect.height),
                      rl.Color(CARD_BG.r, CARD_BG.g, CARD_BG.b, a8))
    rl.draw_rectangle(int(rect.x) + CARD_WIDTH - 1, int(rect.y), 1, int(rect.height),
                      rl.Color(CARD_BORDER.r, CARD_BORDER.g, CARD_BORDER.b, a8))

    total_h = ICON_SIZE + 2 + 58 + 4 + 22
    # keep clear of the torque bar at its full 27px height
    y = rect.y + (rect.height - 30 - total_h) / 2
    cx = rect.x + CARD_WIDTH / 2

    if self._icon is not None:
      rl.draw_texture_ex(self._icon, rl.Vector2(cx - ICON_SIZE / 2, y), 0, 1.0, rl.Color(255, 255, 255, a8))
    y += ICON_SIZE + 2

    w = measure_text_cached(self._font_bold, self._distance_text, 58).x
    rl.draw_text_ex(self._font_bold, self._distance_text, rl.Vector2(cx - w / 2, y), 58, -1, rl.Color(255, 255, 255, a8))
    y += 58 + 4

    fs = 22
    w = measure_text_cached(self._font_medium, self._street_text, fs).x
    while w > CARD_WIDTH - 10 and fs > 14:
      fs -= 1
      w = measure_text_cached(self._font_medium, self._street_text, fs).x
    rl.draw_text_ex(self._font_medium, self._street_text, rl.Vector2(cx - w / 2, y), fs, 0,
                    rl.Color(STREET_COLOR.r, STREET_COLOR.g, STREET_COLOR.b, a8))

  def _draw_trip(self, rect: rl.Rectangle, alpha: float) -> None:
    a8 = int(255 * alpha)
    white = rl.Color(255, 255, 255, a8)
    x = rect.x + CARD_WIDTH + 24
    total_h = 60 + 8 + 60 + 12 + 22
    y = rect.y + (rect.height - 30 - total_h) / 2

    # big time and distance remaining stacked
    for value, unit in self._trip_rows:
      rl.draw_text_ex(self._font_bold, value, rl.Vector2(x, y), 60, -1, white)
      w = measure_text_cached(self._font_bold, value, 60).x
      rl.draw_text_ex(self._font_medium, f" {unit}", rl.Vector2(x + w, y + 60 - 32), 28, 0,
                      rl.Color(UNIT_COLOR.r, UNIT_COLOR.g, UNIT_COLOR.b, a8))
      y += 60 + 8

    if self._advice_text:
      rl.draw_text_ex(self._font_bold, self._advice_text, rl.Vector2(x, y + 4), 22, 0,
                      rl.Color(ADVICE_COLOR.r, ADVICE_COLOR.g, ADVICE_COLOR.b, a8))
