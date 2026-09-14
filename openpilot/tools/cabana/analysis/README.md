# Analysis workspaces

Cabana opens native analysis workspaces with `--layout openpilot/tools/cabana/layouts/tuning.json`
(paths relative to the calling directory), or through **Charts → Workspace**.
The menu also saves, imports, duplicates, and renames pages and lists bundled presets.
Drag a chart's dock tab to move or float it. Dock tabs preserve separate plots;
**Merge** overlays their curves. Drag browser entries onto plots to add curves.
The Charts toolbar's Functions menu creates and edits Python functions and shows
per-function diagnostics. Each chart menu provides transforms, labels, bounds,
line/step/scatter styles, splitting, and visible-range CSV export.

Workspace version 1 stores pages, stable pane and equation IDs, bindings, curve
presentation, optional Y limits, view ranges, and semantic docking trees. Splits
use `x`/`y` axes and a fraction of the remaining region. Leaves store stable window
identities and the selected dock tab. Floating groups use main-viewport-relative
geometry. ImGui owns arrangement changes between import/reset/page transitions;
resizing never rebuilds the saved tree. Session settings also retain ImGui state.
Missing bindings survive DBC or route replacement. Closing plots does not remove
equations. The old saved CAN chart groups and donor `columns + tabs` documents
migrate; grid geometry is inferred because those formats did not store splitters.

## Samples and equations

The analysis session shares immutable CAN, cereal, and derived snapshots, plus
transformed and display buffers. DBC edits invalidate decoded CAN caches. Replay
and live workers extract numeric cereal fields, array indices, enums, and the
`__valid`, `__logMonoTime`, and `__logMonoTimeSeconds` metadata. Deprecated paths
are available through the browser toggle. Metadata tooltips explain enum values.

Equation inputs and returned timestamps are boot seconds. Plot and CSV timestamps
are route-relative seconds. Equations use the primary input's samples in order;
additional inputs use nearest samples, choosing the later sample on equal-distance
ties and clamping at endpoints. Each revision reinitializes Python globals and
recomputes the dependency graph. This also applies when late secondary data changes
nearest matches. Cancellation stops obsolete work; stale results cannot publish.
The preceding completed result may remain visible while a new source revision is
being evaluated. Definition changes clear it immediately.

Only the validated scalar numeric Python language is supported. There is no Lua
runtime or arbitrary script/import support. The bundled Python translations are
explicit, audited inputs to `convert_layouts.py`, not an automatic Lua translator.
Unsupported XML features or untranslated functions fail conversion.

Transform ordering is scale/value offset, analysis, then time offset. Derivatives
emit at the **previous** sample timestamp. Divisor zero selects elapsed time;
a positive divisor selects fixed differences. Nonpositive elapsed time or a
negative fixed divisor emits no derivative. Duplicate samples remain ordered;
non-finite inputs break transform continuity, and non-finite outputs are omitted.
Integration uses positive-time trapezoids; moving averages use a trailing sample
window. A full snapshot recomputation resets all state and joins segment boundaries
in timestamp order. Display reduction happens after analysis.

## Validation

Build Cabana and its native tests with SCons, then run:

```sh
openpilot/tools/cabana/tests/test_cabana
openpilot/tools/cabana/tests/test_analysis
openpilot/tools/cabana/tests/test_workspace_ui
python -m unittest openpilot.tools.cabana.tests.test_equations openpilot.tools.cabana.tests.test_layouts
```

The layout fixtures cover all 14 XML documents: 23 pages, 89 plots, 212 curves,
17 Python definitions, 25 derivatives (21 fixed, four elapsed-time), and three
affine transforms. They check names, colors, aliases, bounds, ranges, and original
N-way split fractions. Native tests round-trip the actual chart model, exercise
shared CAN/display caches, DBC removal/replacement, mixed-input equations, late
inputs, stale-job cancellation, dependency errors, live cereal extraction, and
semantic docking. Numerical tests check timestamps as well as values, state reset,
nearest alignment, and the tuning layout's five-second engagement gate.

`tests/benchmark_workspaces.py` measures repeated visible speed panes with a local
route; `CABANA_PROFILE` enables its frame-time CSV instrumentation. A cached
60-second route (`5beb9b58bd12b691/0000010a--a51155e496`), Xvfb, and software OpenGL
on this development machine produced:

| Visible panes | First cereal snapshot (s) | Peak RSS (MiB) | Median frame (ms) | p95 frame (ms) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.745 | 327.2 | 22.46 | 24.70 |
| 8 | 0.730 | 325.8 | 22.68 | 25.45 |
| 24 | 0.744 | 325.1 | 23.61 | 26.25 |

Frame timings exclude intentional frame pacing. These are warm-cache software
rendering measurements, not a hardware-independent performance guarantee.

The real UI was exercised on `can-states`, `camera-timings`, `locationd_debug`,
`gps_vs_llk`, and `tuning`, including missing bindings on a newer route. Interactive
checks covered resizing, page switching, floating, dock tabs, pane closure, and
restart restoration. Replacing replay with an empty live stream retained chart
definitions. A Ford CAN speed (converted from kph) and `/carState/vEgo` overlaid
with video; seeking the plot updated playback. At an inspected sample, their
values were 20.950 and 20.934 m/s respectively.

`tests/smoke_streams.py` launches the real application on an X display and publishes
synthetic cereal messages through isolated local msgq and loopback ZMQ. Both paths
published 59 numeric fields. Build `openpilot/cereal/messaging/bridge` and use this
checkout's Python msgq extension: extensions from another worktree can have an
incompatible shared-memory layout. The loopback check exercises the remote bridge
transport; it does not substitute for testing physical Panda/SocketCAN hardware.
