# mici nav-only onroad UI: handoff

## Goal

A navigation-first onroad UI for the comma four (mici, 536x240). No camera feed. The
screen exists to answer three questions at a glance: what's my next maneuver, how far
away is it, and how much of the trip is left. Everything else (lane changes, alerts,
openpilot confidence, steering torque) layers on top of that without competing with it.

Design principles that came out of iteration, in priority order:

1. Directions and remaining time/miles are the focus. Arrow and maneuver distance are
   big. No clock / ETA; only "min" and "mi" remaining.
2. One visual pattern per concept. All alerts look the same, all lane changes look the
   same. No per-state special cases.
3. Nothing alarming unless it is an alarm. Lane changes never use red, orange, amber,
   or teal. Only real alerts get the orange/red gradient.
4. Secondary indicators get out of the way. The confidence ball is only on screen in
   plain cruise.

## Files

- `references/nav_ui_mock.html`: interactive browser mock at 2x scale. Buttons drive
  every state, left/right toggle picks the lane side. Source of truth for the visual
  design.
- `openpilot/selfdrive/ui/mici/onroad/nav_ui_demo.py`: raylib port as a mici `Widget`.
  No input; auto-cycles every state on a ~45 s loop so it can be judged on device.
  Reuses `ConfidenceBall(demo=True)` from the real UI. Alert typography follows
  `alert_renderer.py` (DISPLAY weight, lowercase, font-size tiers by string length).
- `openpilot/selfdrive/assets/icons_mici/onroad/blind_spot_left_white.png`: the stock
  blind spot icon recolored white at commit time (the stock asset is orange). Exempted
  from LFS in `.gitattributes` because the fork can't push new LFS objects to comma's
  gitlab.

Both the mock and the demo must be updated together for every change.

## Layout (536x240)

- Left card, 240 px wide, `#101014`: maneuver icon at 120 px (from
  `selfdrive/assets/navigation/direction_*.png`), maneuver distance at 58 px bold
  ("0.4 mi" / "800 ft"), street name at 22 px. Content is centered in the height minus
  30 px so the torque bar never clips it at full height.
- Right panel: "28 min" and "19.3 mi" stacked at 60 px bold with 28 px dim units, then
  a small green (`#80d8a6`) line: lane advice when active ("Move right"), otherwise a
  preview of the next maneuver ("then Mission Blvd").
- Confidence ball: the real widget, radius 24, flush to the right edge, wanders
  vertically with confidence.
- Torque bar: thin strip along the bottom edge, not the on-device arc. Gray track,
  center-out white fill, height grows 8 to 27 px as |torque| goes 0.5 to 1, fill blends
  toward orange near max.

## Lane changes

Mirrors `LaneChangeState`: announce, preLaneChange (nudge required), laneChangeStarting/
Finishing. All three demo sequences (nav nudgeless, nav with nudge, user blinker) share
one treatment:

- Direction: a big flashing turn signal arrow (`turn_signal_left.png` at native
  208x192, flipped for right) on the side of travel, blinking at the 80 BPM heartbeat
  cadence from `alert_renderer.py`. This replaced an earlier pulsing edge-glow
  gradient.
- State text: centered in the space beside the arrow, never under it. Wraps to two
  lines at the space nearest the middle and shrinks to fit.
- Color is keyed to the initiator, constant across the whole sequence:
  openpilot/nav-initiated is calm blue `#4da6ff`, human-initiated is white.
- Nav content ghosts to 8 %, confidence ball fades out.

## Alerts

Every alert uses exactly one pattern (blind spot, prompt, critical are the demo set):

- Full-screen: solid color for the top 20 %, gradient to fully transparent below.
  Orange `(255,115,0)` for user prompts, red `(255,0,21)` for critical.
- Nav content ghosts to 8 % underneath so the transparent region reads as transparent.
  Confidence ball fades out.
- Text block centered horizontally and vertically, lowercase, DISPLAY weight. Optional
  icon left of the text (blind spot uses the white recolor). Subtitle at 26 px centered
  under the title; when a subtitle is present the title drops one size tier to make
  room. Title shrinks until it fits the width.

A solid full-bleed alert background was tried and rejected; keep the gradient.

## Running on device

The device (`comma@10.0.0.22`) runs from `/data/openpilot` on the `navigation` branch
of the `fork` remote. Python lives in `/usr/local/venv`.

```sh
ssh comma@10.0.0.22 'sudo systemctl stop comma'
ssh comma@10.0.0.22 'cd /data/openpilot && bash tools/op.sh switch fork navigation'
# op switch resets submodules; rebuild once after switching:
ssh comma@10.0.0.22 'cd /data/openpilot && PATH=/usr/local/venv/bin:$PATH PYTHONPATH=/data/openpilot /usr/local/venv/bin/python openpilot/system/manager/build.py'
ssh -f comma@10.0.0.22 'cd /data/openpilot && PYTHONPATH=/data/openpilot nohup /usr/local/venv/bin/python openpilot/selfdrive/ui/mici/onroad/nav_ui_demo.py > /tmp/nav_demo.log 2>&1 < /dev/null &'
```

Iterate by scp'ing `nav_ui_demo.py` and restarting (`pkill -f nav_ui_demo.py`; note a
bare `pkill -f nav_ui_demo` also matches the ssh command line and kills your own
shell). Screenshot with the `mici` skill: `mici --host comma@10.0.0.22 capture out.png`.
Restore openpilot with `sudo systemctl start comma`.

## Open questions

- The lane-advice / "then ..." line is still the original mint green `#80d8a6`. If blue
  is "openpilot guidance", that line probably wants to match.
- Blind spot alert always shows the left icon; the real UI flips it by blinker side.
- The demo has no real data plumbing. Wiring it up means driving `MANEUVERS` from
  `navInstruction`, lane state from `modelV2.meta.laneChangeState` /
  `laneChangeDirection` plus `carState` blinkers, and alerts from `selfdriveState`
  exactly as `alert_renderer.py` does.
