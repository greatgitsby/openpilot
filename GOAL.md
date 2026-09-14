# PlotJuggler analysis workflows in Cabana

Port the analysis features used by openpilot's shipped PlotJuggler layouts into Cabana, using independent dockable chart panes, a persistent workspace model, and shared analysis data. Preserve Cabana's CAN reverse-engineering workflows and integrate cereal telemetry and Python-derived series alongside them.

This document defines the implementation target and sequence. The source audit is complete; runtime, numerical, and UI parity still require validation.

## Product requirements

- Support N independently dockable chart panes. Each pane contains one plot with one or more overlaid curves and fills its available width and height.
- Use ImGui docking for pane placement, resizing, floating, and dock tabs. Replace the single Charts window's custom grid, column layout, scrolling, and chart-position drag machinery.
- Distinguish dock tabs within a location from named workspace pages that switch complete arrangements, such as Lateral and Longitudinal.
- Plot CAN signals, cereal fields, and derived series through a common series interface, including mixed overlays.
- Share playback time, inspection cursor, and linked time ranges across charts and video. Keep per-chart vertical limits independent.
- Preserve workspace definitions when changing routes, streams, or DBCs. Unresolved signals remain visible as missing bindings and reconnect when their data becomes available.
- Support Python equations only. Do not add a Lua runtime or general Lua-to-Python translator.
- Preserve the useful analysis features from the previous Cabana PR: field browsing, custom function editing, scaling, derivatives, integration, moving averages, presets, and visible-data CSV export.

## Workspace baseline refinement

- Keep a single top-level workspace selector. Default is the built-in CAN reverse-engineering workspace; named pages and dock splits live inside each workspace.
- New workspaces and pages may start blank. Add Widget offers CAN Messages, Signal Details, Series Browser, Plot, Road Camera, Wide Camera, and Cabin Camera.
- Persist widget visibility per page alongside dock arrangements. Camera panes are independently dockable and share one playback controller.
- Keep the timeline and playback controls at the bottom of Cabana across every workspace. Switching workspaces preserves the loaded stream, playback position, speed, and linked range.

## Required UI implementation approach

New feature UI must use or extend Cabana's existing UI components instead of calling ImGui directly to build equivalent controls or panels.

- Inspect the existing components before adding UI. Reuse `ui/util.h`, `ui/dropdown.h`, `ui/dialogs/`, `ui/widgets/`, and the shared theme, icons, toolbar, input, tooltip, and window helpers.
- Use existing helpers such as `iconButton`, `inputText`, `inputTextMultiline`, `drawToolbar`, dropdown items, file dialogs, and message boxes where applicable.
- When a component lacks a needed capability, extend it or extract a reusable component in the appropriate shared UI module. For example, promote the existing panel wrapper into a reusable dockable-panel component for chart windows.
- Encapsulate necessary low-level ImGui docking calls in a shared workspace/docking component. Keep low-level ImGui and ImPlot calls inside reusable component and renderer implementations; feature screens should compose those components.
- Preserve consistent spacing, colors, focus behavior, disabled states, tooltips, menus, and floating-window behavior through the existing components and theme. Avoid parallel implementations and screen-specific styling fixes.
- Let ImGui manage docking through that component boundary. Do not introduce a second custom positioning system or a generic widget framework.

## Source baseline and reuse

Build on current Cabana and selectively extract code from [commaai/openpilot PR #38792](https://github.com/commaai/openpilot/pull/38792), branch `feat/cabana-plotjuggler`, audited at `b59b4cf152752080a78594392574412ef0869b3c`. Adapt the extracted code to current APIs and lifetimes rather than carrying over the entire stale branch.

The PlotJuggler reference is [commaai/PlotJuggler](https://github.com/commaai/PlotJuggler/tree/a196f90e17c78b68586f112145a4f3259992c642), audited at `a196f90e17c78b68586f112145a4f3259992c642`. The original layouts are in `openpilot/tools/plotjuggler/layouts/`.

The 14 audited XML layouts contain 23 workspace tabs, 89 time-series plots, 212 curve placements, 25 derivative transforms, 3 scale/offset transforms, and 17 custom equation definitions. They also use plot titles, colors, aliases, proportional splitters, saved ranges, optional Y bounds, and relative time. All plotted styles in this corpus are lines. Plugin inventory entries alone do not establish a requirement to port those plugins.

Paths in this table are relative to `openpilot/tools/cabana/` in the donor PR:

| Donor code | Planned use |
| --- | --- |
| `analysis/fields.h`, `analysis/fields.cc` | Reuse cached cereal extraction, immutable sample snapshots, and merge preparation in the shared series layer. Preserve `__valid`, `__logMonoTime`, and `__logMonoTimeSeconds` paths. |
| `analysis/logfields.h`, replay/live stream changes | Adapt background extraction, cancellation, ordered merging, and synthetic video-event exclusion to current stream lifetimes. Remove analysis-layer dependencies on UI worker headers. |
| `analysis/equations.h`, `analysis/equations.cc`, `analysis/cabana_equations.py` | Reuse the scalar Python evaluator, validated numeric language, nearest-sample lookup, and equation state initialization. |
| `ui/chart/signaltree.h` | Reuse hierarchical filtering, numeric array-index ordering, expansion state, and visible-row traversal. |
| `ui/chart/functioneditor.cc` | Extract an independent editor using shared UI components and the analysis model. Use stable equation IDs so display names can change. |
| `ui/chart/analysis.h` | Reuse integral and moving-average logic; extend transform settings and output representation for reference-compatible derivatives. |
| `ui/chart/workspace.cc` | Extract CSV export, preset discovery, and asynchronous equation scheduling into separate services. Replace the chart-owned layout and data responsibilities. |
| `layouts/*.json` | Reuse signal selections, colors, titles, bounds, and Python equation translations. Recover layout geometry and missing presentation metadata from the original XML. |
| `tests/test_cabana.cc`, `tests/test_equations.py`, `tests/test_layouts.py` | Carry forward relevant regression coverage and adapt it to the new model. Add reference tests where the old implementation differs from PlotJuggler. |

JotPluggler may supply additional extraction, browser, or layout implementation ideas after auditing them. Prefer the donor PR's Cabana integration where it fits. JotPluggler's vectorized Python sampling and derivative timestamps differ from the PlotJuggler reference and must not silently define compatibility behavior.

## Architecture and ownership

### Analysis session

- A shared series store exposes CAN, cereal, and derived samples through stable series references.
- CAN references resolve through Cabana's DBC manager; persistent definitions do not retain raw `cabana::Signal*` pointers. DBC edits invalidate affected runtime bindings and caches.
- A derived-series engine owns evaluation jobs, dependency ordering, cached results, and diagnostics. It operates independently of chart visibility or existence.
- A time controller owns playback position, inspection cursor, and linked view ranges. Explicitly distinguish boot timestamps supplied to imported equation translations from route-relative display time.
- Reuse samples and transformed results across panes. Decode or evaluate a source once per relevant revision, and downsample only for display after transformation.

### Workspace document

- Use a versioned native document containing named pages, stable pane IDs, chart definitions, equation definitions, and dock arrangements.
- Charts reference sources and equations by stable identity, independently of labels or vector position.
- Each page describes an arrangement of chart panes and existing Cabana panels. Shared Messages, Details, and Video components can retain their own content state while their placement changes by page.
- Store chart titles, curve labels and colors, visibility, style, transforms, ranges, and optional Y bounds.
- The workspace outlives the current route or stream. Closing a chart releases a view; it does not delete shared data or equation definitions.

### Docking and presentation

- Each chart window has a persistent identity such as `###Chart/<uuid>` and renders through a shared dockable-panel component.
- ImGui owns the live arrangement. Build docking nodes on creation, import, or reset, then capture changes for persistence. Do not rebuild docking from a stale application tree on resize.
- Keep inactive workspace dockspaces alive when switching pages.
- Normalize shareable arrangements into proportional splits, tabbed leaves, pane IDs, selected dock tabs, and floating placements. Keep machine-specific window geometry in session settings.
- ImGui INI state complements semantic layout persistence; it cannot represent signal bindings or equations by itself.
- Dropping a signal onto a plot adds an overlay. Dragging a pane's dock tab moves or tabs that pane. Explicit merge combines curves; docking windows together preserves separate charts. Splitting a chart's signals creates separate panes.

## Python and numerical compatibility

Reuse the donor PR's per-sample Python evaluator and translated bundled equations. Preserve its numeric-language validation and tests. Python is the only equation language exposed or executed by Cabana.

- Evaluate equations sequentially on the primary source's timestamps, with nearest-sample lookup for additional inputs. Match reference tie-breaking and endpoint behavior.
- Preserve equation globals between samples within an evaluation. Reset state deterministically when recomputing from earlier data. Support the tuning layout's five-second engagement gating.
- Keep reference-compatible timestamp handling for equations returning a value or a `(time, value)` pair.
- Order dependencies, report cycles and missing inputs distinctly, and show errors per equation. Discard stale background results after document or session revisions change.
- Define how streaming results are recomputed when an additional source arrives later and changes nearest-sample selection.
- Distinguish actual-time derivatives from fixed-divisor sample differences. Of the audited derivative transforms, 21 use a fixed divisor of `1.0` and 4 use actual elapsed time.
- Match the reference derivative's output timestamp: the previous sample's timestamp. Skip the first sample and nonpositive divisors. The donor implementation currently uses elapsed time and the current timestamp, so it needs adaptation.
- Preserve scale, value offset, time offset, and transform aliases in the model and conversion. Specify transform ordering explicitly.
- Audit non-finite values, empty inputs, duplicate timestamps, segment boundaries, and source replacement so compatibility differences are deliberate and tested.

The original XML is the reference for layout geometry and numerical behavior. Ship the bundled layouts as native Cabana documents with Python equations already translated. A one-way XML importer may import supported structural and plotting features, but must report unsupported Lua equations explicitly. Never execute Lua, silently drop equations, or claim arbitrary Lua import support.

## Implementation sequence

1. **Independent CAN chart panes.** Refactor current charts into dockable windows using shared UI components. Replace fixed chart height with available dimensions, assign stable IDs, and preserve shared zoom, cursor, scrubbing, line/step/scatter styles, overlays, and downsampling. Completion: multiple charts independently dock beside existing panels and restore after restart.

2. **Persistent workspaces.** Introduce the document and docking components, named pages, capture/restore, duplication, renaming, and session-independent chart definitions. Migrate current saved chart groups and the donor PR's `columns + tabs[charts]` format using the information each actually contains. Completion: workspace contents and arrangements survive restarts, page changes, and route replacement.

3. **Shared series and cereal browser.** Extract the donor's field store, background indexing, and signal tree. Integrate CAN and cereal through the same series interface, retaining metadata paths, enum information, list indices, and explicit access to deprecated fields. Completion: a cereal speed and a decoded CAN speed overlay in one pane and stay synchronized with video; unresolved bindings reconnect when available.

4. **Derived series and editor.** Extract the Python runtime, editor, worker scheduling, and tests into the new ownership model. Add dependency diagnostics and revision-based caching; preserve integration, moving averages, scaling, and visible-data CSV export. Completion: equations can consume shared series, remain available after chart closure, and produce deterministic results after source updates.

5. **Bundled layout fidelity.** Combine the donor's Python translations and chart settings with the original XML geometry, ranges, and aliases. Convert N-way split fractions into successive binary splits relative to the remaining space. Add preset selection and layout open/save/CLI support using existing UI components. Completion: all 14 reference layouts have native equivalents and round-trip without losing required content or placement.

6. **End-to-end validation.** Verify numerical results, docking interactions, save/restore, route and DBC changes, local/remote cereal streaming, and performance as pane counts increase. Completion requires evidence for both the reference workflows and existing CAN reverse-engineering behavior.

## Acceptance evidence

- Structural fixtures verify tab names, pane counts, curve bindings, original split proportions, colors, aliases, bounds, and Python equation definitions for all 14 layouts.
- Numerical fixtures verify exact output timestamps and expected values for fixed and actual-time derivatives, scale/offset, nearest-sample alignment, equation globals, engagement gating, and out-of-order segment arrival. Extend the donor tests instead of treating their existing derivative expectations as reference parity.
- Exercise `can-states` for nested geometry, `camera-timings` for pages and fixed differences, `locationd_debug` for metadata and bounds, `gps_vs_llk` for multi-input math and deprecated fields, and `tuning` for stateful equations and overlays.
- UI evidence covers resizing, docking, floating, dock tabs, workspace switching, pane closure, restart restoration, and retained definitions across route changes. Verify consistent behavior through shared UI components.
- Repeated views of the same source share extraction and evaluation. Record loading time, memory, and frame time with representative routes and increasing pane counts; hidden panes must not trigger unnecessary rendering or duplicate analysis work.
- Preserve existing DBC editing, CAN decoding, signal actions, video synchronization, and live CAN workflows throughout the sequence.

## Scope boundaries

- No Lua runtime or general Lua translator.
- No requirement to port PlotJuggler's entire plugin ecosystem, XY plots, or unused analysis tools to satisfy the audited layout corpus.
- No default nested multi-chart grid inside a chart pane.
- No direct ImGui implementation of feature controls when Cabana has an existing component or can extend one; keep low-level calls behind shared component boundaries.
- No wholesale rebase of the donor branch or duplication of fixes already present in current Cabana.
