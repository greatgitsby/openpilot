#include "tools/cabana/ui/widgets/scrollabletabbar.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <vector>

#include "imgui_internal.h"

namespace {
float scrollButtonsWidth() {
  const ImGuiStyle &style = ImGui::GetStyle();
  return ImGui::GetFrameHeight() * 2.0f + style.ItemInnerSpacing.x + style.ItemSpacing.x * 2.0f;
}

// the pair of chevron buttons at pos, each `size` big and `spacing` apart, scrolling tab_bar
void drawScrollButtons(ImGuiTabBar *tab_bar, const ImVec2 &pos, const ImVec2 &size, float spacing) {
  const float max_scroll = std::max(0.0f, tab_bar->WidthAllTabs - tab_bar->BarRect.GetWidth());
  const ImVec2 backup_pos = ImGui::GetCursorScreenPos();

  ImGui::PushItemFlag(ImGuiItemFlags_ButtonRepeat, true);
  for (int i = 0; i < 2; ++i) {
    const bool left = i == 0;
    ImGui::SetCursorScreenPos(ImVec2(pos.x + i * (size.x + spacing), pos.y));
    ImGui::BeginDisabled(left ? tab_bar->ScrollingTarget <= 0.0f : tab_bar->ScrollingTarget >= max_scroll);
    if (ImGui::Button(left ? "###scroll_left" : "###scroll_right", size)) {
      const float step = (left ? -4.0f : 4.0f) * ImGui::GetFontSize();
      tab_bar->ScrollingTarget = std::clamp(tab_bar->ScrollingTarget + step, 0.0f, max_scroll);
      tab_bar->ScrollingAnim = tab_bar->ScrollingTarget;
    }
    // the icon font glyph sits off center in its padded advance, so the chevron is drawn in the rect
    const ImVec2 c((ImGui::GetItemRectMin().x + ImGui::GetItemRectMax().x) * 0.5f,
                   (ImGui::GetItemRectMin().y + ImGui::GetItemRectMax().y) * 0.5f);
    const float h = std::round(ImGui::GetFontSize() * 0.25f);
    const float dx = left ? h * 0.5f : -h * 0.5f;
    ImDrawList *painter = ImGui::GetWindowDrawList();
    painter->PathLineTo(ImVec2(c.x + dx, c.y - h));
    painter->PathLineTo(ImVec2(c.x - dx, c.y));
    painter->PathLineTo(ImVec2(c.x + dx, c.y + h));
    painter->PathStroke(ImGui::GetColorU32(ImGuiCol_Text), ImDrawFlags_None, 1.5f);
    ImGui::EndDisabled();
  }
  ImGui::PopItemFlag();
  ImGui::SetCursorScreenPos(backup_pos);
}

void drawScrollButtons(ImGuiTabBar *tab_bar) {
  const ImGuiStyle &style = ImGui::GetStyle();
  const float size = ImGui::GetFrameHeight();
  drawScrollButtons(tab_bar, ImVec2(tab_bar->BarRect.Max.x + style.ItemSpacing.x, tab_bar->BarRect.Min.y), ImVec2(size, size), style.ItemInnerSpacing.x);
}

// the wheel scrolls the tabs while the pointer is over them: a two finger swipe on a touchpad, or a
// mouse wheel like a window that only scrolls sideways. Owning the wheel keeps the window behind still
void scrollTabBarWithWheel(ImGuiTabBar *tab_bar) {
  ImGui::SetKeyOwner(ImGuiKey_MouseWheelX, tab_bar->ID);
  ImGui::SetKeyOwner(ImGuiKey_MouseWheelY, tab_bar->ID);
  const ImGuiIO &io = ImGui::GetIO();
  const float wheel = io.MouseWheelH + io.MouseWheel;
  if (wheel != 0.0f) {
    const float max_scroll = std::max(0.0f, tab_bar->WidthAllTabs - tab_bar->BarRect.GetWidth());
    const float step = std::floor(ImGui::GetFontSize() * 2.0f);
    tab_bar->ScrollingTarget = std::clamp(tab_bar->ScrollingTarget - wheel * step, 0.0f, max_scroll);
    tab_bar->ScrollingAnim = tab_bar->ScrollingTarget;
  }
}

struct ScrollableTabBar { ImGuiTabBar *tab_bar; bool overflowing; };
std::vector<ScrollableTabBar> scrollable_tab_bars;
}  // namespace

bool beginScrollableTabBar(const char *str_id, ImGuiTabBarFlags flags) {
  // the buttons take their room from the bar when the tabs overflowed last frame
  ImGuiWindow *window = ImGui::GetCurrentWindow();
  ImGuiTabBar *prev_tab_bar = ImGui::TabBarFindByID(window->GetID(str_id));
  const bool overflowing = prev_tab_bar && prev_tab_bar->WidthAllTabsIdeal > prev_tab_bar->BarRect.GetWidth() + 1.0f;
  const float backup_work_max_x = window->WorkRect.Max.x;
  if (overflowing) window->WorkRect.Max.x -= scrollButtonsWidth();
  const bool open = ImGui::BeginTabBar(str_id, flags | ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_NoTabListScrollingButtons);
  window->WorkRect.Max.x = backup_work_max_x;
  if (open) scrollable_tab_bars.push_back({ImGui::GetCurrentTabBar(), overflowing});
  return open;
}

void endScrollableTabBar() {
  ImGui::EndTabBar();
  const ScrollableTabBar bar = scrollable_tab_bars.back();
  scrollable_tab_bars.pop_back();
  if (!bar.overflowing) return;
  drawScrollButtons(bar.tab_bar);
  ImGuiTabBar *tab_bar = bar.tab_bar;
  if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(tab_bar->BarRect.Min, tab_bar->BarRect.Max)) {
    scrollTabBarWithWheel(tab_bar);
  }
}

// imgui lays out a dock node's tab bar with its own arrows (TabBarScrollingButtons) when the tabs overflow: two
// (font size - 2) wide buttons at the right end of the bar, and the bar rect shrinks by their width plus one.
// They are painted over with the title bar background and the chevron buttons are drawn in their place, in a
// small input-taking window on top of the host, so the clicks land on ours
void overrideDockNodeScrollButtons() {
  ImGuiContext &g = *ImGui::GetCurrentContext();
  const ImVec2 button_size(g.FontSize - 2.0f, ImGui::GetFrameHeight());
  const float buttons_width = button_size.x * 2.0f;
  for (int n = 0; n < g.DockContext.Nodes.Data.Size; ++n) {
    ImGuiDockNode *node = (ImGuiDockNode *)g.DockContext.Nodes.Data[n].val_p;
    if (!node || !node->TabBar || !node->HostWindow || !node->IsVisible || node->IsHiddenTabBar() || node->IsNoTabBar()) continue;
    ImGuiTabBar *tab_bar = node->TabBar;
    if (tab_bar->CurrFrameVisible != g.FrameCount && tab_bar->PrevFrameVisible != g.FrameCount) continue;
    // the bar rect is already reduced when the arrows are shown, so this is "ideal > the full bar width"
    if (tab_bar->Tabs.Size < 2 || tab_bar->WidthAllTabsIdeal <= tab_bar->BarRect.GetWidth() + buttons_width + 1.0f) continue;

    const ImVec2 pos(tab_bar->BarRect.Max.x + 1.0f, tab_bar->BarRect.Min.y);
    char name[48];
    snprintf(name, sizeof(name), "##dock_tab_scroll_%08X", node->ID);
    ImGui::SetNextWindowPos(pos);
    ImGui::SetNextWindowSize(ImVec2(buttons_width, button_size.y));
    ImGui::SetNextWindowViewport(node->HostWindow->Viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(1.0f, 1.0f));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoFocusOnAppearing |
                                   ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollWithMouse;
    if (ImGui::Begin(name, nullptr, flags)) {
      ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
      ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + buttons_width, pos.y + button_size.y),
                                                ImGui::GetColorU32(node->IsFocused ? ImGuiCol_TitleBgActive : ImGuiCol_TitleBg));
      drawScrollButtons(tab_bar, pos, button_size, 0.0f);
    }
    ImGui::End();
    ImGui::PopStyleVar(3);

    // the wheel over the tabs, hovering the host window (the tab bar belongs to it, not to the docked windows)
    if (g.HoveredWindow && g.HoveredWindow->RootWindowDockTree == node->HostWindow->RootWindowDockTree &&
        ImGui::IsMouseHoveringRect(tab_bar->BarRect.Min, tab_bar->BarRect.Max, false)) {
      scrollTabBarWithWheel(tab_bar);
    }
  }
}

