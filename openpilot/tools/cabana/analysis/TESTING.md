# Analysis validation

Validated on Linux using software OpenGL, Xvfb and real xdotool mouse/keyboard events. Each UI run has isolated settings, an X11 display and messaging prefixes; WAYLAND_DISPLAY is removed so tests cannot attach to the user's desktop.

## Results

Build succeeded. Both native test binaries passed. Python: **9 passed**. Full Xvfb run: **14 passed in 66.69 seconds**. After the tab-order persistence change, its new test and the split/undo/save regression both passed (**2 passed in 6.17 seconds**), giving 15 distinct UI cases. Ruff and `git diff --check` passed.

## Automated coverage

- Native analysis tests: cereal numeric reflection, enums, lookup, timestamp ordering, derivatives, duplicate timestamps, retention, malformed layouts, and round trips of all 16 Cabana presets and 17 existing Jotpluggler JSON layouts.
- Native existing Cabana tests: pass.
- Python tests: nine cases covering NumPy expressions, globals, additional-channel alignment, scalar and explicit-time results, invalid results, every PlotJuggler XML preset, map cache and invalid bounds.
- Xvfb tests: browsing/plotting, Python preview/apply/timeout recovery, 100 random seeks, repeated tab creation, malformed layout recovery, local and remote all-service streaming, retention and pause/resume, dense logs, simultaneous four-camera seeking, derivative editing, split/undo/save, log-row seeking, local route selectors q/r/a, map seeking/zoom, closing during damaged-log loading, decoded CAN/multiple selection, and saved tab ordering.

The dense fixture has 100,000 carState events, 11,706,000 numeric samples, 10,000 log lines and 1,000 thumbnails. It must stay below 1.5 GB RSS and above 10 FPS; an observed completed run reported approximately 46 FPS. The repeated-seek test limits RSS growth to 150 MB. Live tests inject malformed packets and enforce a one-second retained analysis window. The Python timeout test deliberately runs an infinite loop and then successfully evaluates another expression. Camera fixtures deliberately contain reordered/B-frames and distinct colors to expose decoder sharing errors.

The tests exposed and led to fixes for unsafe ReplayStream casts with direct logs, independent cameras sharing a decoder, delayed/B-frame decoding, log selection outside the first column, saved-tab restoration, and stale asynchronous results. Additional lifecycle fixes guard route loading after window destruction, release inactive camera panes, and key retained thumbnails by timestamp.

## Reproduce

From the repository root, with project dependencies and the testing extra installed:

```sh
scons -j8 openpilot/tools/cabana/cabana openpilot/tools/cabana/tests/test_analysis openpilot/tools/cabana/tests/test_cabana
openpilot/tools/cabana/tests/test_analysis
openpilot/tools/cabana/tests/test_cabana
python -m pytest -q openpilot/tools/cabana/tests/test_analysis_python.py
CABANA_E2E=1 python -m pytest -q -s openpilot/tools/cabana/tests/test_analysis_ui.py
```

The UI tests additionally require Xvfb, xdotool, Pillow, and FFmpeg with libx264/libx265. Fixtures are generated locally; no private route or physical device is required. Screenshots and diagnostic JSON remain in pytest's temporary directories. Review captures from this implementation session are in `/tmp/cabana-validation/overview/overview.png` and `/tmp/cabana-validation/cameras/overview.png`.

Physical Panda/SocketCAN devices, live VisionIPC camera producers, authenticated remote routes, and availability of the public Overpass service were not exercised. Remote cereal streaming was tested through real local ZMQ bridges. Street-cache rendering inputs and bounds were tested without depending on the public service. The rolling limit applies to analysis samples; Cabana's existing raw CAN recording/history retains its existing behavior.

## Reference provenance

Behavioral research used commaai/PlotJuggler commit `a196f90e17c78b68586f112145a4f3259992c642`, including its cereal parser, subscriber, derivative/scale transforms, custom-function alignment and plot layout serialization. Jotpluggler was inspected for workflows and JSON data compatibility. Cabana's implementation is independently written; no source code was copied from either application. Presets translate the repository's PlotJuggler XML layout data.
