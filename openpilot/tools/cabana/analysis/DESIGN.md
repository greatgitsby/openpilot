# Cabana analysis workspace

## Design

Cabana becomes a single route investigation application. CAN inspection and DBC editing remain available; an Analysis workspace adds all working Jotpluggler workflows. A shared stream owns samples, and Cabana's playback position drives plots, logs, GPS, thumbnails and cameras. Switching workspace does not reload a route or create another clock.

The Analysis sidebar searches numeric cereal fields and decoded CAN signals by path, shows values and enum labels at the cursor, supports multiple selection and dragging into plots, and hides deprecated fields by default. Special entries add map, thumbnail and camera panes. The workspace contains named tabs with freely split, resizable panes. Plots share a time viewport and tracker; users can seek, play, pause, change speed, step, loop, follow live data, zoom and reset the view. Missing channels stay in layouts and resolve when data arrives.

Each curve has a label, color, visibility, scale, offset and optional first derivative using actual or specified dt. A Python editor produces named derived series from an input and additional channels, offers preview and errors, and supports NumPy arrays and explicit (times, values) results. Logs expose severity, source, search, context and route/boot/wall time, with click-to-seek. GPS supports pan, zoom, follow and click-to-seek. Media panes use Cabana's existing video support where possible.

Layouts persist tabs, splits, curves, transforms, axis limits and custom definitions independently of route data. Save/load, autosave, reset, duplicate/rename/close tabs and structural undo/redo are first-class actions. Jotpluggler JSON and PlotJuggler XML are import formats; bundled presets are independently generated from PlotJuggler's layout data. Import never requires linking or launching Jotpluggler. Screenshot output supports reproducible headless rendering.

Route loading retains Cabana's asynchronous resolver/cache and accepts local logs and route slices. Local MSGQ and remote ZMQ receive all cereal services, with a configurable rolling analysis buffer, pause and follow. CAN DBC changes invalidate decoded channels. Existing CAN/Panda/SocketCAN workflows continue to work.

## Behavioral research

Read commaai/PlotJuggler source (checkout in /tmp/cabana-plotjuggler-reference): DataLoadRlog/rlog_parser.cpp, DataStreamCereal/datastream_cereal.cpp, plotwidget.cpp, transforms/{first_derivative,scale_transform,custom_function}.cpp. Numeric leaves use slash paths, array indices and numeric enums; event metadata belongs under each service. Streaming is non-conflated. Derivatives omit the first point and nonpositive intervals, and use the preceding timestamp. Layouts retain source names, colors, transforms and limits. Custom functions align additional channels to the reference timeline. No source from either reference application is copied into Cabana.

## Implementation sequence

1. Add a GUI-independent numeric/event store with dynamic cereal reflection, ordered batch merge, metadata, logs, thumbnails and live retention. Feed it from replay and live streams; add direct log loading.
2. Add the Analysis workspace, browser, shared timeline and plots. Reuse Cabana DBC decoding and camera/thumbnail primitives. Implement pane splitting and tabs, map and log views.
3. Add curve transforms and isolated Python evaluation, layout persistence/import, autosave and undo/redo; presets and CLI capture options.
4. Build Cabana and run numerical/parser/layout tests. Generate a deterministic cereal fixture with CAN, numeric arrays/enums, GPS, logs and thumbnails. Run Cabana under Xvfb and exercise input-driven browse/plot/seek/transform/layout/log/map/media flows; capture screenshots and assert state. Test all-service live streaming and existing Cabana checks.

## Acceptance checklist

- [x] Numeric cereal browser, metadata, enums, arrays, deprecated filter, multi-select/drag
- [x] Replay/local file/route slices; all-service local/remote live with retention
- [x] CAN and sendcan decoding; DBC reload/editor integration
- [x] Shared tracker, playback/speed/step/loop/follow, zoom and axis limits
- [x] Tabs and resizable split panes; rename/duplicate/remove; undo/redo
- [x] Curve visibility/labels/colors, derivative, scale/offset
- [x] Python derived series, extra inputs, preview, errors and persistence
- [x] Logs with severity/source/search/context/time modes and seek
- [x] GPS map pan/zoom/follow/seek, thumbnails and camera panes
- [x] Layout save/load/autosave/reset and existing presets/import
- [x] CLI compatibility and screenshot capture
- [x] Core tests and Xvfb end-to-end evidence

Implementation and test evidence, including external hardware/service limits, are recorded in [TESTING.md](TESTING.md).
