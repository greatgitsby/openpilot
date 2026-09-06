# Cabana bug-fixing handoff

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
