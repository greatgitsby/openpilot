# Cabana bug-fixing handoff

## Native macOS integration update — 2026-09-06

This section supersedes the testing instructions and environment below. The user now requires **Computer UI testing on the real demo route; do not use fixtures or Xvfb**. Launch the binary with `--demo`. They want analysis integrated into Cabana and reported whole-UI hitches when segments merge/load. Changes below are included in the Cabana integration update on `jp-slop`.

### Implementation

- CAN and Analysis now share the application shell, workspace switches, timeline, playback/speed controls, and status footer. CAN docking survives workspace switches. File/Edit actions adapt to the active workspace.
- Replay merges build analysis snapshots and event indices on the merge worker, then publish by swapping on the UI thread. Channel samples use copy-on-write storage. Native tests cover snapshot isolation across trim and merge.
- Replay CAN chart rebuilding runs asynchronously without waiting for worker futures on the UI thread. Analysis CAN histories decode on demand in workers; the browser caches its hierarchy, plots cache decimation, and formula input serialization runs in workers. Jobs retain copied signal definitions and shared event storage.
- Analysis cameras use persistent workers with replaceable pending requests, keeping the existing bounded frame cache. Old seek results cannot replace a closer displayed frame. Cached download paths are memoized after resolution to avoid repeated Python launches, with file existence checked before reuse.
- Main-thread seek acknowledgement runs directly instead of waiting for a queued main-thread callback. Route-end seeks clamp inside the final segment.
- ImGui keyboard navigation is enabled. Cmd/Ctrl+1 and +2 switch workspaces. Focused timeline supports Home/End and Left/Right (Shift for 10-second steps). Space controls playback without activating focused navigation buttons.

- Follow-up: scrub previews now render above the shared timeline in the foreground, clamped to the viewport, instead of covering/replacing the original camera pane. Thumbnail collection also runs while that pane is hidden. Native build passed; Computer could not reliably trigger timeline hover in the follow-up check.

- Visual follow-up: analysis now uses theme-aware slate/white surfaces, stronger labels and borders, consistent padding and rounded controls, a full-width signal search with column headers, titled panes with right-aligned Options menus, and centered camera images. Plot colors adapt in brightness for the active theme without modifying layout colors. Map route and position have distinct blue/orange styling. No animation or extra camera decode work was added.
- Visual validation used Computer with real `--demo` routes in `cameras-and-map` and `camera-timings`, in both light and dark mode. Checked pane layout, cameras, plot legends/axes/curves, and search focus. Primary text/panel contrast is 12.89:1 dark and 14.12:1 light; secondary labels are 6.98:1 and 5.69:1 respectively (palette calculation, not an exhaustive accessibility audit). Native build and diff whitespace checks passed. Switched the saved theme while Cabana was closed because Computer could not send the settings shortcut; restored the original dark theme afterward.

- Connect palette follow-up: cloned `greatgitsby/connect` into `/Users/trey/dev/connect`, added `commaai/connect` as `upstream`, and fast-forwarded local `master` by nine commits to `7091050543687f3841f2942fc8bf3f2bf258d0b6`, matching upstream master. GitHub origin was not pushed. Palette source is `src/colors.js` and `src/theme.js`: background `#1D2225`, panels `#30373B`, primary `#57A9E3`, neutral grey controls. Connect only defines dark mode; Cabana light mode uses Connect's lightGrey/lightBlue colors. This supersedes the earlier slate palette and contrast figures: primary text is now 11.47:1 dark / 16.04:1 light; secondary is 6.56:1 / 6.59:1. Native build and diff checks passed; Computer inspected the real demo camera/map layout in both themes. Original dark preference restored.

- Crop follow-up: replay analysis cameras and thumbnail panes now use the shared `videoPlacement(..., settings.crop_video)` helper, matching the existing live/CAN camera behavior. The preference is read on every draw without restarting decoders. Native build and diff checks passed; Computer inspected real demo cameras with crop enabled (fill) and disabled (centered letterbox), changing the saved setting while closed. Original crop-on preference restored. Thumbnail placement shares the helper but was not separately exercised in the UI.

- Video frame follow-up: media panes have a theme-aware rounded border with zero inner padding. Replay, thumbnail, and live camera textures use `AddImageRounded` so opaque video pixels do not cover the rounded corners. Native build/diff checks passed and Computer inspected the real demo.

- Final polish: checkboxes use Cabana's compact checkbox control while keeping button sizing. Table headers and alternating rows have stronger contrast. Media borders draw after the image using the same bounds and radius, with no padding. Core analysis tests and final diff checks passed before committing.

### Validation and limits

- Full native macOS Cabana build and `openpilot/tools/cabana/tests/test_analysis` passed; `git diff --check` passed.
- Computer tested the real 16-minute demo route with `--layout cameras-and-map`: three cameras visibly update; workspace switching preserves playback; paused Home/End/Right seeks preserve pause and timeline focus; Space does not open a focused Layouts menu. Earlier native checks also exercised search and playing seeks. No exhaustive preset sweep was performed.
- Computer can capture screenshots and send keyboard input. Its coordinate clicks often hover without activating controls. The user confirmed their own mouse works normally. Do not count failed Computer clicks as functional passes or infer broken Cabana mouse handling. ImGui content is absent from the native accessibility tree; a native accessibility bridge would improve semantic targeting. No bridge was implemented.
- Settled playback showed roughly 120 FPS in an earlier native check, but sparse Computer screenshots are not a frame-latency benchmark. Worst-case segment-merge and camera latency remain unquantified. Do not claim all hitches are eliminated.
- Legacy fixture UI tests were not used after the user's correction and were not migrated to the shared footer. Historical measurements below are not measurements of this native build.

Computer on this machine needs an app bundle to target Cabana. `/tmp/Cabana Integration.app` wraps the built binary (symlink under Contents/MacOS). Launch used:

```sh
open -n '/tmp/Cabana Integration.app' \
  --env 'PATH=/Users/trey/dev/openpilot/.venv/bin:/usr/bin:/bin' \
  --env 'PYTHONPATH=/Users/trey/dev/openpilot' \
  --args --demo --layout cameras-and-map
```

Current workspace is `/Users/trey/dev/openpilot`. Build with the project `.venv/bin` on PATH. Older Linux paths and push instructions below are historical, not instructions for this session.

## Historical handoff

## Current mode and user priorities

We are in **bug-fixing mode**. Do not restart the migration or add unrelated features.

The initial request was to move Jotpluggler functionality into Cabana: design first, plan implementation, independently write the implementation, read PlotJuggler source for behavior, and stress-test end to end with Xvfb. No Jotpluggler source was copied. The implementation and subsequent fixes are on **`origin/jp-slop`** in `greatgitsby/openpilot`.

The user subsequently requested testing every preset because **cameras-and-map played roughly one frame every five seconds**. They emphasized that seeking anywhere in a loaded/cached route should be effectively immediate. Then they explicitly narrowed the scope: **stop the broader preset sweep for now, finish the camera fix, and make timeline-bar seeks preserve playback**. Resume additional bug fixing when requested; do not claim every preset has been exercised.

## Changes already made

- `7f4cde901`: independently implemented the Cabana analysis workspace, layout/import/presets, Python series, numeric cereal/CAN streams, map/log/media views, CLI capture and tests.
- `0da834d0f`: fixed macOS Clang `-Werror=shadow` in `AnalysisWorkspace::browser`. Linux's `-Wshadow=local` had missed it. A complete macOS build has **not** been verified here.
- Latest camera/timeline fix on `jp-slop`:
  - `FFmpegVideoDecoder::decodeIndependent` previously restarted from frame zero whenever a frame was skipped. Sustained playback became progressively expensive after a missed frame.
  - Forward skipping now continues decoding. For video without B-frames, large and backward seeks start at the nearest indexed keyframe. The actual openpilot encoder declares `b_frames = 0` (`openpilot/system/loggerd/loggerd.h`) and short GOPs.
  - Analysis camera panes keep a bounded 32 MiB decoded-image LRU each, so recently displayed frames can be uploaded directly. Inactive panes still release their camera objects/cache.
  - Reordered/B-frame streams retain the presentation-frame counter. Uncached backward seeks for those streams still use the conservative start-of-file fallback; do not promise instant arbitrary B-frame seeking.
  - Timeline slider no longer calls `pause(true)`. Playing seeks keep playing; paused seeks stay paused. Explicit step/plot/log/map interactions retain their previous behavior.

## Latest validation

Linux build passed. Changed C++ translation units were also checked using Clang with `-Wshadow -Werror=shadow`; this is not a substitute for building on macOS.

A minute-long fixture with three 1920×1080 HEVC cameras was driven through real mouse/keyboard input under Xvfb:

- Before fix, at 4× playback: only **3 displayed updates per camera in 5 seconds**, with about **15 seconds** maximum lag.
- After forward-decoding fix on the same reordered-video probe: **192 updates per camera in 5 seconds**, maximum lag about **0.16 seconds**.
- Focused regression with openpilot-style non-B-frame video: first distant seeks about **97 ms**, repeated cached seeks about **47 ms**, including xdotool and polling overhead. At 4× playback: **151 updates per camera in 4 seconds**, maximum lag **0.252 seconds**.
- **3 focused tests passed in 9.25 seconds**: HD playback/cached seeking, existing four-camera forward/backward seek regression, and timeline playback-state preservation.
- Ruff passed for changed Python tests; `git diff --check` passed.

These are synthetic-fixture measurements on Linux. Do not describe them as guaranteed instantaneous performance or real-route/macOS measurements. Read `TESTING.md` for the earlier validation; its 15-case UI coverage was **not an exhaustive preset sweep**.

## Reproduce

From the repository root with project dependencies available:

```sh
scons -j8 openpilot/tools/cabana/cabana
CABANA_E2E=1 python -m pytest -q -s \
  openpilot/tools/cabana/tests/test_analysis_playback.py \
  openpilot/tools/cabana/tests/test_analysis_ui.py \
  -k 'hd_camera or four_cameras or timeline_seek'
```

The HD test creates a minute-long 1080p fixture; generation takes time. Requirements: Xvfb, xdotool, pytest, Pillow, FFmpeg with libx264/libx265. Tests explicitly remove `WAYLAND_DISPLAY`, isolate XDG settings and messaging, and drive real X11 input. Do not accidentally attach a test to the user's desktop.

This Linux workspace is `/home/tam/.t3/worktrees/openpilot/t3code-51fe46ab`. Its local branch is `t3code/move-jotpluggler-to-cabana`; push using `HEAD:refs/heads/jp-slop`. The shared environment is `/home/tam/Work/openpilot/.venv/bin`; temporary pytest/Ruff dependencies are under `/tmp/cabana-test-deps`. For this machine:

```sh
PATH=/home/tam/Work/openpilot/.venv/bin:$PATH \
PYTHONPATH=/tmp/cabana-test-deps:$PWD \
CABANA_E2E=1 CABANA_PRESET_FIXTURE=/tmp/cabana-presets-hd \
python -m pytest -q -s \
  openpilot/tools/cabana/tests/test_analysis_playback.py \
  openpilot/tools/cabana/tests/test_analysis_ui.py \
  -k 'hd_camera or four_cameras or timeline_seek'
```

`CABANA_PRESET_FIXTURE` is optional and reuses an existing fixture. `/tmp/cabana-presets-hd` also contains numeric signals prepared during the abandoned broader sweep, adding some workload. New fixture generation in the committed focused test is self-contained.

Local evidence: `/tmp/cabana-camera-regression.log`, `/tmp/cabana-playback-before-fast.json`, `/tmp/cabana-playback-after-fast.json`, `/tmp/cabana-camera-fix-build.log`. Earlier screenshots and logs: `/tmp/cabana-validation/`.

The repository's pre-push hook invokes `.venv/bin/git-lfs`, but this worktree has no `.venv`. Pushes used a temporary `core.hooksPath` containing the equivalent pre-push hook with the absolute shared-environment git-lfs path. **Preserve LFS processing; do not bypass the hook.** No permanent hook/config change was made.

## Where to resume when asked

1. Ask for/observe results on the user's Mac and actual cached route. Investigate remaining camera seek/playback latency before broadening scope.
2. Finish the postponed **every-preset, every-tab** Xvfb sweep with suitable data. All JSON layouts previously parsed/round-tripped, but that does not validate playback, populated plots, formulas, or runtime behavior.
3. Known issue discovered but intentionally left unfixed after the user narrowed scope: `layouts/driver-monitoring-debug.json` references `/driverMonitoringState/awarenessStatus` and `/driverMonitoringState/isDistracted`, which do not exist in the current schema. Current fields are under `visionPolicyState`, including `awarenessPercent` and `isDistracted`. Check units and historical-route compatibility before changing the preset. A temporary edit was reverted; the issue remains.
4. Test real-route segment-boundary seeking, repeated pane/tab switching, cache eviction, rapid alternating seeks during playback, and memory on long routes. Current cache is per pane and bounded, not a guarantee that every decoded frame or route segment is resident.
5. Physical Panda/SocketCAN, real live VisionIPC cameras, authenticated remote routes, and public Overpass availability remain unverified. Remote cereal transport was tested through local real ZMQ bridges.

Key files: `ui/widgets/analysiscamera.{cc,h}`, `tools/replay/framereader.{cc,h}`, `ui/analysis.cc`, `tests/test_analysis_playback.py`, `tests/test_analysis_ui.py`, and `tests/analysis_fixture.py` under Cabana unless otherwise specified. Refer to `DESIGN.md` for the original architecture, but treat claimed feature completion separately from remaining bug-fixing validation.
