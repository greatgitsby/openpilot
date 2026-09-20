This is `imgui_widgets.cpp` from Dear ImGui commit
`934c6a5f5ef2355d6df25395d555cb71f790c4e9`, matching the `comma-deps-imgui`
dependency. Its MIT license is included alongside it.

The prebuilt library has no callback for customizing native docking tab overflow.
In particular, floating dock groups draw during `NewFrame`, before application
code can amend their tab bars. Cabana compiles this translation unit instead of
the archive's widget object so every tab bar can use the existing shared controls
without platform-specific linker hooks or changes to docking behavior.

The local changes are limited to:

- Including `scrollabletabbar.h` and checking the ImGui version.
- Selecting the scroll fitting policy in `BeginTabBarEx`.
- Delegating overflow buttons and wheel input to the shared Cabana component.

When updating ImGui, replace this file from the matching dependency revision and
reapply those three integration points. Keep the remaining upstream code intact.
