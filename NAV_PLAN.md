# Navigation re-add plan

Bring back minimal navigation: routing and turn-by-turn instructions, a small onroad
instruction overlay, and nav-driven turn desires into the driving model. No map rendering,
no nav model.

Port base: `3b8ed67aa^` (commit before "remove navigation" #32773, June 2024). All paths
below are under `openpilot/`.

## Scope

In:
- `navd`: Mapbox Directions routing, step tracking, `navInstruction` / `navRoute`.
- Onroad overlay: next maneuver icon, distance, instruction text, ETA.
- Model hookup: map maneuvers to `Desire.turnLeft/turnRight/keepLeft/keepRight`.
- Toggle next to Driving Personality; Mapbox token set by the user via params.

Out:
- Map rendering (`mapsd`, mapbox-gl-native), nav model (`navmodeld`), map settings UI,
  comma connect destinations, comma maps proxy, speed limit control.

## Steps

### 1. cereal
- `cereal/log.capnp`: rename `navInstructionDEPRECATED @82` to `navInstruction @82` and
  `navRouteDEPRECATED @83` to `navRoute @83`. Structs `NavInstruction`, `NavRoute` already
  exist; no new ordinals. Leave `navModel`, `navThumbnail`, `mapRenderState` deprecated.
- `cereal/services.py`: `"navInstruction": (True, 1., 10)`, `"navRoute": (True, 0., 1)`.

### 2. Params (`common/params_keys.h`)
- `NavDestination`, `NavDestinationWaypoints`: `CLEAR_ON_MANAGER_START | CLEAR_ON_OFFROAD_TRANSITION`, JSON.
- `MapboxToken`: `PERSISTENT`, STRING. User sets it from a shell; navd idles if empty.
- `NavigationEnabled`: `PERSISTENT`, BOOL, default off. Gates navd and everything downstream.

### 3. navd
- `selfdrive/navd/{navd.py,helpers.py,set_destination.py}` ported from the base commit.
- Position: `gpsLocation` (qcom) / `gpsLocationExternal` (ublox), whichever is valid and
  fresh. Valid when `hasFix` and `horizontalAccuracy < 50 m`. Bearing only when
  `speed > 2 m/s`. Drop the laikad branch. navd writes `LastGPSPosition` every ~10 s.
- Token: `MapboxToken` param only, against `api.mapbox.com`.
- Keep step tracking, banner parsing, reroute logic; raise `REROUTE_COUNTER_MIN` 3 -> 5
  for raw GPS jitter. Keep the `managerState` UI-restart route resend.
- `system/manager/process_config.py`: `PythonProcess("navd", ..., and_(only_onroad, nav_enabled))`.
- `selfdrive/test/test_onroad.py`: add navd to the CPU table.
- `system/athena/athenad.py`: re-add `setNavDestination` RPC from the base commit.

### 4. Settings toggle
- Tici `selfdrive/ui/layouts/settings/toggles.py`: add `NavigationEnabled` to `_toggle_defs`,
  inserted right after `LongitudinalPersonality`, `needs_restart=True`.
- Mici `selfdrive/ui/mici/layouts/settings/toggles.py`:
  `BigParamControl("navigation", "NavigationEnabled", toggle_callback=restart_needed_callback)`
  after the personality toggle.

### 5. Onroad overlay
- `selfdrive/ui/ui_state.py`: subscribe to `navInstruction`.
- New `selfdrive/ui/onroad/nav_renderer.py` (`Widget`, same shape as `HudRenderer`):
  icon, `maneuverDistance` in user units, `maneuverPrimaryText`, ETA line from
  `timeRemaining` / `distanceRemaining`. Visible only when `navInstruction` is valid and
  received after `started_frame`. Top-left below the 300 px header.
- Lane advice from `modelV2.meta.navLaneAdvice`: "Move left" / "Move right" line under
  the instruction with a chime on change. Display only; no logic in the UI.
- `selfdrive/ui/onroad/augmented_road_view.py`: render after HUD, before alerts. Mici
  onroad layout gets the same widget scaled down.
- Icons: `selfdrive/assets/navigation/direction_*.png` from the base commit via
  `git lfs fetch origin 758a9f3ef` (verified fetchable). Only the mapped subset. Textures
  cached at init.

### 6. Nav driving logic: `selfdrive/controls/lib/nav_helper.py`
All nav-to-driving business logic lives in this one module (`NavHelper`), run by modeld at
20 Hz next to `DesireHelper`. navd stays pure routing and knows nothing about lanes or
desires. The UI displays `NavHelper` output; it never re-derives it.

Inputs: `navInstruction` (+ valid/fresh), `carState` (vEgo, blinkers, steeringPressed,
blindspots), `modelV2` lane lines / probs / road edges, `latActive`, `DesireHelper` state.

Outputs:
- `desire`: `none`, `turnLeft/Right`, `keepLeft/Right`, `laneChangeLeft/Right`.
- `lane_advice`: `none`, `moveLeft`, `moveRight`, plus whether it is auto or driver-prompted.
Published by modeld in `modelV2.meta` (new `navLaneAdvice` field) for the UI and logs.

Logic inside `NavHelper`:
- Maneuver desire. `left/right/sharp *` on `turn`, `end of road`, `continue`, `new name` ->
  `turnLeft/Right`. `slight *` and `fork`, `off ramp`, `on ramp`, `merge` -> `keepLeft/Right`.
  `uturn`, `roundabout`, `rotary`, `arrive`, `depart`, `straight` -> none. Windows: turns
  `10 m < dist < max(45 m, 2 s * v_ego)` and `v_ego < 15 m/s`; keeps
  `dist < max(60 m, 3 s * v_ego)` and `v_ego > 8 m/s`. One pulse per maneuver via a latch
  reset when distance grows. modeld rising-edge pulses `desire_pulse`, so the helper holds
  the desire high for the window.
- Lane positioning. Side to be on comes from the next maneuver modifier and Mapbox lane
  guidance (`navInstruction.lanes`). Rules, one lane change at a time:
  - After an on-ramp / merge step completes: advise one change away from the merge side
    once the far-side lane line is probable.
  - Approaching an exit or turn: from `max(0.8 km, 60 s * v_ego)` out, advise changes toward
    the maneuver side until the road edge on that side is within one lane width.
  - Between maneuvers: no advice.
- Lane checks (used for both advice validity and auto execution): adjacent lane exists
  (lane line prob on that side, road edge not within one lane width), `v_ego` above
  `LANE_CHANGE_SPEED_MIN`, BSM clear on that side, no driver blinker or steering override,
  15 s debounce, max consecutive changes in one direction (3).
- Execution tiers:
  - Driver-prompted (default): `lane_advice` is shown in the UI with a chime; the driver
    flicks the blinker and the normal `DesireHelper` lane change runs.
  - Auto (`NavAutoLaneChange` param, default off, requires `CP` BSM support): `NavHelper`
    emits `laneChangeLeft/Right` itself when all lane checks pass.
- Precedence: driver blinker lane change (`DesireHelper`) always wins; nav desire is
  suppressed when lateral is inactive, any blinker is on, or a lane change is active.

Integration: `modeld.py` subscribes to `navInstruction`, calls `NH.update(...)` after
`DH.update(...)`, and uses `DH.desire if DH.desire != none else NH.desire`. `DesireHelper`
itself is unchanged.

Params: `NavDesireEnabled` (hidden, default off) gates any nav desire so turn-by-turn can
be validated before the model is steered; `NavAutoLaneChange` gates tier 2.

### 7. Tests
- `selfdrive/navd/tests/test_navd.py`: canned Mapbox directions fixture, mocked
  `requests.get`. Covers step advance at 10 m, monotonic `maneuverDistance`, remaining
  distance/time sums, reroute only after debounce, destination reached clears
  `NavDestination`, `parse_banner_instructions` on a captured banner.
- `selfdrive/controls/lib/tests/test_nav_helper.py`: table-driven maneuver mapping,
  windows, speed gates, one rising edge per maneuver; lane advice for on-ramp, exit
  approach, and in-town turn sequences using synthetic lane lines / road edges; lane
  checks (BSM, missing adjacent lane, debounce, consecutive cap); blinker precedence.
- `selfdrive/test/process_replay/process_replay.py`: add `navInstruction` to modeld pubs.
- On-device: enable toggle, set token, `set_destination.py <google maps url>`, confirm
  `navInstruction` on the bus and the overlay before enabling `NavDesireEnabled`.

## Order
1. Steps 1-3 (messages, params, navd, athena).
2. Steps 4-5 (toggle, overlay), testable with replay or a fake publisher.
3. Step 6, on-road with both params as gates.

## Risks
- Raw GPS is noisier than the old Kalman position: more spurious reroutes, mitigated by the
  debounce bump.
- Wrong `turnLeft` at speed is a safety issue: conservative mapping, speed gates, lateral
  active gate, and the separate desire param.
- Model desire is advisory; the model decides whether and when it completes a turn. Expect
  good behavior on exits and forks, weaker on arbitrary intersections.
- No lane index or side-traffic sensing exists beyond BSM and lane-line heuristics, so auto
  lane changes stay off by default and require BSM; multi-lane crossings in town remain
  driver-prompted.
