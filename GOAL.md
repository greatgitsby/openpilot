# Cabana workspace redesign

Restructure Cabana around sources, independent widgets, a shared timeline, and persisted workspaces. Bring the workspace concept from `pj` into the current Cabana, while making multi-route analysis quick and pleasant to use.

## Sources and playback

- Open multiple routes at once. Support both independent playback and optional synchronized playback.
- Let users align corresponding moments between routes, then play, seek, or step through them together. Alignment offsets relate route time to workspace time.
- Arrow keys step through camera frames, including while paused. Support looping a chosen interval, such as ten seconds.
- Keep CAN messages, openpilot messages, CAN inspection, DBCs, and editing state associated with their source. Allow signals from different routes on the same chart.
- Keep playback controls in a persistent timeline area rather than making them another movable widget.

## Widgets and layout

- Every chart is its own independently dockable tab. Remove the enclosing chart widget and its internal layout system.
- Charts, videos, browsers, and inspectors can share tab groups, dock beside one another, or float. Tabs are not restricted to a particular widget container.
- Each available video stream can become its own tab. Offer camera tabs based on files that exist; remove the video stream selector.
- Each camera tab independently chooses Fit (whole frame) or Fill (crop to fill).
- Put the Fit/Fill button over the video, eliminating its separate toolbar row. It is 66% transparent when not hovered and fully opaque on hover.
- Adding any base widget should take one or two clicks, with customization available afterward.

## Workspaces and persistence

- Saved presets become complete workspaces, not merely chart layouts. Persist widget configuration, docking, source assignments, camera framing, and timeline synchronization and loop settings.
- Workspaces are named, selectable, and saveable to disk for reopening and sharing.
- Selecting a workspace and opening its saved routes are separate actions. Including route references is optional.
- Shared files store references only. Do not bundle logs or video; referenced data is loaded separately.
- New workspaces start blank. The Default workspace resembles traditional Cabana.
- Built-in workspaces can be reset to their original layouts. Their edits stay in memory and are not saved to disk; duplicate one to keep a custom version.
- Live streaming should have an appropriate default widget set. Whether it needs additional dedicated widgets remains open.

## Timeline experience

Make route tracks feel like a video editor such as Final Cut Pro or iMovie: taller video bars, actual thumbnails, a readable time ruler, clear playheads, and event-color ribbons overlaid on the clips. Scrubbing and frame stepping should update video responsively. Generate and cache thumbnails asynchronously.

The timeline lives in a resizable bottom drawer that expands or collapses while keeping playback controls available. Custom workspaces remember its expanded height and collapsed state. Long source names elide and remain vertically centered when selected, with the full name shown once in the tooltip.

## Implementation and delivery

- Use existing shared Cabana components for buttons, inputs, menus, and other controls. Extend those components when necessary.
- Build with subagents; all future agents must use low reasoning effort.
- After implementation, test the actual UX and refine it. Verify multiple routes, independent and linked playback, exact frame stepping, loops, camera framing, widget creation/docking, and workspace save/reopen behavior.
- Preserve compatibility with existing saved chart layouts where practical.
- The requested integration target is `pj2`; incorporate the latest upstream `master` and commit/push the authorized work there.
