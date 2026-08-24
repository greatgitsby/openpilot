#!/usr/bin/env python3
"""Demo of the nav-only onroad UI concept (references/nav_ui_mock.html).

Runs standalone and cycles through every state automatically:
cruise, nav lane change (nudgeless + nudge), user lane change,
blind spot, prompt and critical alerts.
"""
import math
import time

import pyray as rl

from openpilot.selfdrive.ui.mici.onroad.confidence_ball import ConfidenceBall
from openpilot.system.ui.lib.application import gui_app, FontWeight
from openpilot.system.ui.lib.text_measure import measure_text_cached
from openpilot.system.ui.widgets import Widget
from openpilot.common.filter_simple import FirstOrderFilter

CARD_WIDTH = 240
ICON_SIZE = 120
EDGE_GLOW_WIDTH = 70
BLINK_PERIOD = 0.75

SIM_SPEED = 40.0  # sim seconds per real second
SIM_MPH = 42.0
TRIP_MILES = 19.3
TRIP_SECS = 28 * 60

# icon, street, distance (mi), lane advice
MANEUVERS = [
  ("direction_turn_slight_right", "Fremont Blvd", 0.4, "Move right"),
  ("direction_turn_right", "Mission Blvd", 1.2, None),
  ("direction_on_ramp_slight_left", "I-880 N via ramp", 0.7, "Move left"),
  ("direction_continue_straight", "Continue on I-880 N", 8.5, None),
]

ADVICE_COLOR = rl.Color(128, 216, 166, 255)
STREET_COLOR = rl.Color(185, 185, 192, 255)
UNIT_COLOR = rl.Color(133, 133, 142, 255)
TRIP_COLOR = rl.Color(207, 207, 214, 255)
CARD_BG = rl.Color(16, 16, 20, 255)
CARD_BORDER = rl.Color(34, 34, 34, 255)

LANE_COLORS = {
  "req": rl.Color(255, 255, 255, 230),
  "pre": rl.Color(255, 200, 0, 255),
  "go": rl.Color(0, 255, 204, 255),       # openpilot-initiated: engaged teal
  "go_user": rl.Color(255, 255, 255, 230),  # human-initiated: override white
}

ORANGE = (255, 115, 0)
RED = (255, 0, 21)

# (mode, duration s, arg) looped forever
# lane arg: (state, label, side); alert arg: key
TIMELINE = [
  ("idle", 5.0, None),
  # nav lane change, nudgeless
  ("lane", 1.5, ("req", "lane change for I-880 N", "right")),
  ("lane", 2.5, ("go", "changing lane", "right")),
  ("idle", 3.0, None),
  # nav lane change, nudge required
  ("lane", 1.5, ("req", "lane change for I-880 N", "left")),
  ("lane", 2.5, ("pre", "steer left to confirm", "left")),
  ("lane", 2.5, ("go", "changing lane", "left")),
  ("idle", 3.0, None),
  # user lane change (blinker)
  ("lane", 2.5, ("pre", "steer right to start", "right")),
  ("lane", 2.5, ("go_user", "changing lane", "right")),
  ("idle", 3.0, None),
  # plain turn signals: big flashing arrows
  ("blinker", 3.5, "left"),
  ("idle", 1.5, None),
  ("blinker", 3.5, "right"),
  ("idle", 3.0, None),
  # alerts
  ("alert", 4.0, "blocked"),
  ("idle", 2.0, None),
  ("alert", 4.0, "prompt"),
  ("idle", 2.0, None),
  ("alert", 4.0, "critical"),
  ("idle", 4.0, None),
]

# one pattern for every alert: full-screen top gradient, centered lowercase text,
# optional icon left of the text block. text1, text2, color, blind spot icon
ALERTS = {
  "blocked": ("car in blind spot", "", ORANGE, True),
  "prompt": ("pay attention", "steer required", ORANGE, False),
  "critical": ("take control immediately", "system unresponsive", RED, False),
}


def fmt_dist(mi: float) -> tuple[str, str]:
  ft = mi * 5280
  if ft < 1000:
    return str(max(0, round(ft / 10) * 10)), "ft"
  return f"{mi:.1f}", "mi"


class NavUIDemo(Widget):
  def __init__(self):
    super().__init__()
    self._font_bold = gui_app.font(FontWeight.DISPLAY)
    self._font_medium = gui_app.font(FontWeight.MEDIUM)
    self._font_regular = gui_app.font(FontWeight.DISPLAY_REGULAR)

    self._icons = {name: gui_app.texture(f"navigation/{name}.png", ICON_SIZE, ICON_SIZE) for name, *_ in MANEUVERS}
    self._bs_icon = gui_app.texture("icons_mici/onroad/blind_spot_left_white.png", 134, 150)
    self._ts_left = gui_app.texture("icons_mici/onroad/turn_signal_left.png", 208, 192)
    self._ts_right = gui_app.texture("icons_mici/onroad/turn_signal_left.png", 208, 192, flip_x=True)

    self._ball = ConfidenceBall(demo=True)
    self._torque_filter = FirstOrderFilter(0.0, 0.1, 1 / gui_app.target_fps)

    # simulated drive
    self._m_idx = 0
    self._m_dist = MANEUVERS[0][2]
    self._miles_left = TRIP_MILES
    self._secs_left = float(TRIP_SECS)
    self._sim_clock = time.time()
    self._last_t = time.monotonic()

    # scene playback
    self._scene_idx = 0
    self._scene_start = time.monotonic()

    # fades
    self._nav_alpha = FirstOrderFilter(1.0, 0.08, 1 / gui_app.target_fps)
    self._overlay_alpha = FirstOrderFilter(0.0, 0.06, 1 / gui_app.target_fps)
    self._ball_alpha = FirstOrderFilter(1.0, 0.1, 1 / gui_app.target_fps)

  # ---------- state ----------

  def _scene(self):
    return TIMELINE[self._scene_idx]

  def _update_state(self):
    now = time.monotonic()
    dt = min(0.1, now - self._last_t)
    self._last_t = now

    # advance scene
    if now - self._scene_start >= self._scene()[1]:
      self._scene_idx = (self._scene_idx + 1) % len(TIMELINE)
      self._scene_start = now

    # simulated drive
    sim_dt = dt * SIM_SPEED
    self._sim_clock += sim_dt
    travelled = SIM_MPH / 3600 * sim_dt
    self._m_dist -= travelled
    self._miles_left = max(0.0, self._miles_left - travelled)
    self._secs_left = max(0.0, self._secs_left - sim_dt)
    if self._m_dist <= 0:
      self._m_idx = (self._m_idx + 1) % len(MANEUVERS)
      self._m_dist = MANEUVERS[self._m_idx][2]
    if self._miles_left <= 0:
      self._miles_left, self._secs_left, self._m_idx = TRIP_MILES, float(TRIP_SECS), 0
      self._m_dist = MANEUVERS[0][2]

    # demo signals for the shared widgets
    t = now
    self._ball.update_filter(0.65 + 0.35 * math.sin(t * 0.35) * math.sin(t * 0.13))
    self._torque_filter.update(0.95 * math.sin(t * 0.9) * math.sin(t * 0.31))

    # fade targets
    mode, _, arg = self._scene()
    # ball fades out for right lane changes / right blinker (it sits on the right edge) and all alerts
    ball_hidden = (mode == "lane" and arg[2] == "right") or (mode == "blinker" and arg == "right") or mode == "alert"
    self._ball_alpha.update(0.0 if ball_hidden else 1.0)
    if mode == "lane":
      self._nav_alpha.update(0.08)
      self._overlay_alpha.update(1.0)
    elif mode == "blinker":
      self._nav_alpha.update(1.0)
      self._overlay_alpha.update(1.0)
    elif mode == "alert":
      # same ghost level as lane changes so the gradient's transparent region
      # reads as transparent on every alert
      self._nav_alpha.update(0.08)
      self._overlay_alpha.update(1.0)
    else:
      self._nav_alpha.update(1.0)
      self._overlay_alpha.update(0.0)

  # ---------- render ----------

  def _render(self, rect: rl.Rectangle):
    a = self._nav_alpha.x
    self._draw_maneuver_card(rect, a)
    self._draw_trip(rect, a)

    # ball renders below any overlay so alerts occlude it naturally
    self._ball.render(rect)
    # fade the ball against the black background while a right lane change runs
    fade = 1.0 - self._ball_alpha.x
    if fade > 0.01:
      rl.draw_rectangle(int(rect.x + rect.width - 48), int(rect.y), 48, int(rect.height),
                        rl.Color(0, 0, 0, int(255 * fade)))
    if a > 0.02:
      self._draw_torque_bar(rect, a)

    mode, _, arg = self._scene()
    if self._overlay_alpha.x > 0.01:
      if mode == "lane":
        self._draw_lane(rect, arg)
      elif mode == "blinker":
        self._draw_blinker(rect, arg)
      elif mode == "alert":
        self._draw_alert(rect, arg)

  def _draw_maneuver_card(self, rect: rl.Rectangle, alpha: float):
    a8 = int(255 * alpha)
    rl.draw_rectangle(int(rect.x), int(rect.y), CARD_WIDTH, int(rect.height),
                      rl.Color(CARD_BG.r, CARD_BG.g, CARD_BG.b, a8))
    rl.draw_rectangle(int(rect.x) + CARD_WIDTH - 1, int(rect.y), 1, int(rect.height),
                      rl.Color(CARD_BORDER.r, CARD_BORDER.g, CARD_BORDER.b, a8))

    icon_name, street, _, _ = MANEUVERS[self._m_idx]
    num, unit = fmt_dist(max(0.0, self._m_dist))
    dist_text = f"{num} {unit}"

    total_h = ICON_SIZE + 2 + 58 + 4 + 22
    # keep clear of the torque bar at its full 27px height
    y = rect.y + (rect.height - 30 - total_h) / 2
    cx = rect.x + CARD_WIDTH / 2

    icon = self._icons[icon_name]
    rl.draw_texture_ex(icon, rl.Vector2(cx - ICON_SIZE / 2, y), 0, 1.0, rl.Color(255, 255, 255, a8))
    y += ICON_SIZE + 2

    w = measure_text_cached(self._font_bold, dist_text, 58).x
    rl.draw_text_ex(self._font_bold, dist_text, rl.Vector2(cx - w / 2, y), 58, -1, rl.Color(255, 255, 255, a8))
    y += 58 + 4

    fs = 22
    w = measure_text_cached(self._font_medium, street, fs).x
    while w > CARD_WIDTH - 10 and fs > 14:
      fs -= 1
      w = measure_text_cached(self._font_medium, street, fs).x
    rl.draw_text_ex(self._font_medium, street, rl.Vector2(cx - w / 2, y), fs, 0,
                    rl.Color(STREET_COLOR.r, STREET_COLOR.g, STREET_COLOR.b, a8))

  def _draw_trip(self, rect: rl.Rectangle, alpha: float):
    a8 = int(255 * alpha)
    white = rl.Color(255, 255, 255, a8)
    x = rect.x + CARD_WIDTH + 24
    total_h = 60 + 8 + 60 + 12 + 22
    y = rect.y + (rect.height - 30 - total_h) / 2

    # big time and miles remaining stacked, no clock
    for value, unit in ((str(round(self._secs_left / 60)), "min"), (f"{self._miles_left:.1f}", "mi")):
      rl.draw_text_ex(self._font_bold, value, rl.Vector2(x, y), 60, -1, white)
      w = measure_text_cached(self._font_bold, value, 60).x
      rl.draw_text_ex(self._font_medium, f" {unit}", rl.Vector2(x + w, y + 60 - 32), 28, 0,
                      rl.Color(154, 154, 162, a8))
      y += 60 + 8

    y += 4
    # small next-up line: lane advice when active, otherwise preview of the next maneuver
    advice = MANEUVERS[self._m_idx][3]
    text = advice if advice else f"then {MANEUVERS[(self._m_idx + 1) % len(MANEUVERS)][1]}"
    rl.draw_text_ex(self._font_bold, text, rl.Vector2(x, y), 22, 0,
                    rl.Color(ADVICE_COLOR.r, ADVICE_COLOR.g, ADVICE_COLOR.b, a8))

  def _draw_torque_bar(self, rect: rl.Rectangle, alpha: float):
    # thin bottom strip, center-out fill: grows 8->27px as |torque| goes 0.5->1,
    # blends white->orange near max (mock's flat variant, not the on-device arc)
    def lerp(a, b, f):
      return a + (b - a) * min(1.0, max(0.0, f))

    def blend(c1, c2, f):
      f = min(1.0, max(0.0, f))
      return tuple(round(v + (w - v) * f) for v, w in zip(c1, c2, strict=True))

    t = self._torque_filter.x
    abs_t = abs(t)
    height = round(lerp(8, 27, (abs_t - 0.5) * 2))
    gray = round(255 * lerp(0.12, 0.3, (abs_t - 0.5) * 2))
    y = int(rect.y + rect.height - height)
    rl.draw_rectangle(int(rect.x), y, int(rect.width), height, rl.Color(gray, gray, gray, int(255 * alpha)))

    cx = rect.x + rect.width / 2
    w = abs_t * rect.width / 2
    heat = max(0.0, abs_t - 0.75) * 4
    c_start = blend((255, 255, 255), (255, 200, 0), heat)
    c_end = blend((255, 255, 255), (255, 115, 0), heat)
    start = rl.Color(*c_start, int(255 * 0.9 * alpha))
    end = rl.Color(*c_end, int(255 * alpha))
    fx = int(cx) if t >= 0 else int(cx - w)
    left, right = (start, end) if t >= 0 else (end, start)
    rl.draw_rectangle_gradient_h(fx, y, int(w), height, left, right)

  def _draw_lane(self, rect: rl.Rectangle, arg):
    state, label, side = arg
    oa = self._overlay_alpha.x
    c = LANE_COLORS[state]

    # flashing turn signal arrow on the side of travel
    self._draw_blinker(rect, side)

    # centered state text
    fs = 52 if len(label) <= 14 else 44 if len(label) <= 22 else 36
    color = rl.Color(c.r, c.g, c.b, int(c.a * oa))
    max_w = rect.width - 2 * EDGE_GLOW_WIDTH
    size = measure_text_cached(self._font_bold, label, fs)
    if size.x > max_w:  # wrap to two lines at the middle space
      mid = label.rfind(" ", 0, len(label) // 2 + 1)
      lines = [label[:mid], label[mid + 1:]] if mid > 0 else [label]
    else:
      lines = [label]
    line_h = fs * 1.05
    ty = rect.y + (rect.height - line_h * len(lines)) / 2
    for line in lines:
      w = measure_text_cached(self._font_bold, line, fs).x
      rl.draw_text_ex(self._font_bold, line, rl.Vector2(rect.x + (rect.width - w) / 2, ty), fs, -0.5, color)
      ty += line_h

  def _draw_blinker(self, rect: rl.Rectangle, side: str):
    # big flashing arrow on the signaling side, Mazda heartbeat cadence
    phase = (time.monotonic() % BLINK_PERIOD) / BLINK_PERIOD
    blink = 1.0 if phase < 0.5 else 0.2
    a8 = int(255 * blink * self._overlay_alpha.x)

    icon = self._ts_left if side == "left" else self._ts_right
    x = rect.x + 16 if side == "left" else rect.x + rect.width - 16 - icon.width
    y = rect.y + (rect.height - icon.height) / 2
    rl.draw_texture_ex(icon, rl.Vector2(x, y), 0, 1.0, rl.Color(255, 255, 255, a8))

  def _draw_alert(self, rect: rl.Rectangle, key: str):
    # every alert follows one pattern: full-screen top gradient, optional icon
    # left of a centered text block, text2 centered under text1
    text1, text2, (r, g, b), bs_icon = ALERTS[key]
    oa = self._overlay_alpha.x

    # solid top 20%, gradient to fully transparent below; whole surface fades with oa
    solid_h = round(rect.height * 0.2)
    color = rl.Color(r, g, b, int(255 * 0.9 * oa))
    clear = rl.Color(r, g, b, 0)
    rl.draw_rectangle(int(rect.x), int(rect.y), int(rect.width), solid_h, color)
    rl.draw_rectangle_gradient_v(int(rect.x), int(rect.y + solid_h), int(rect.width),
                                 int(rect.height - solid_h), color, clear)

    white = rl.Color(255, 255, 255, int(255 * 0.9 * oa))
    icon = self._bs_icon if bs_icon else None
    icon_w = (icon.width + 16) if icon else 0

    fs = 82 if len(text1) <= 12 else 70 if len(text1) <= 16 else 54
    if icon:
      fs -= 10
    if text2:
      fs -= 10  # make room for the larger subtitle
    while fs > 24 and icon_w + measure_text_cached(self._font_bold, text1, fs).x > rect.width - 36:
      fs -= 2
    t1_w = measure_text_cached(self._font_bold, text1, fs).x

    block_x = rect.x + (rect.width - icon_w - t1_w) / 2
    text_h = fs + ((6 + 26) if text2 else 0)
    text_y = rect.y + (rect.height - text_h) / 2

    if icon:
      rl.draw_texture_ex(icon, rl.Vector2(block_x, rect.y + (rect.height - icon.height) / 2), 0, 1.0, white)

    tx = block_x + icon_w
    rl.draw_text_ex(self._font_bold, text1, rl.Vector2(tx, text_y), fs, -1, white)

    if text2:
      dim = rl.Color(255, 255, 255, int(255 * 0.65 * oa))
      w2 = measure_text_cached(self._font_regular, text2, 26).x
      rl.draw_text_ex(self._font_regular, text2, rl.Vector2(tx + (t1_w - w2) / 2, text_y + fs + 6), 26, 0.4, dim)


def main():
  gui_app.init_window("nav ui demo")
  demo = NavUIDemo()
  for _ in gui_app.render():
    demo.render(rl.Rectangle(0, 0, gui_app.width, gui_app.height))


if __name__ == "__main__":
  main()
