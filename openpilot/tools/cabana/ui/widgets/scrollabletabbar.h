#pragma once

#include "imgui.h"

// a tab bar that scrolls with a pair of chevron buttons at its right end when the tabs overflow, in place of
// imgui's small arrows. Use like BeginTabBar/EndTabBar, the fitting policy is always scroll
bool beginScrollableTabBar(const char *str_id, ImGuiTabBarFlags flags = 0);
void endScrollableTabBar();

// Cabana's workspace tab groups, using the same overflow controls as widget tabs.
void scrollableDockSpace(ImGuiID id, const ImVec2 &size);
