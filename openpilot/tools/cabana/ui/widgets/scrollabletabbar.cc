#include "tools/cabana/ui/widgets/scrollabletabbar.h"

#include <algorithm>
#include <cmath>
#include <vector>

#include "imgui_internal.h"

namespace {
float scrollButtonsWidth() {
  const ImGuiStyle &style = ImGui::GetStyle();
  return (ImGui::GetFrameHeight() + style.ItemSpacing.x) * 2.0f;
}

void drawScrollButtons(ImGuiTabBar *tab_bar) {
  const ImGuiStyle &style = ImGui::GetStyle();
  const float size = ImGui::GetFrameHeight();
  const float max_scroll = std::max(0.0f, tab_bar->WidthAllTabs - tab_bar->BarRect.GetWidth());
  const float start_x = tab_bar->BarRect.Max.x + style.ItemSpacing.x;
  const ImVec2 backup_pos = ImGui::GetCursorScreenPos();
  ImGuiWindow *window = ImGui::GetCurrentWindow();
  const bool backup_is_set_pos = window->DC.IsSetPos;

  ImGui::PushItemFlag(ImGuiItemFlags_ButtonRepeat, true);
  for (int i = 0; i < 2; ++i) {
    const bool left = i == 0;
    ImGui::SetCursorScreenPos(ImVec2(start_x + i * (size + style.ItemSpacing.x), tab_bar->BarRect.Min.y));
    ImGui::BeginDisabled(left ? tab_bar->ScrollingTarget <= 0.0f : tab_bar->ScrollingTarget >= max_scroll);
    if (ImGui::Button(left ? "###scroll_left" : "###scroll_right", ImVec2(size, size))) {
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
  window->DC.CursorPos = backup_pos;
  window->DC.IsSetPos = backup_is_set_pos;
}

void scrollWithWheel(ImGuiTabBar *tab_bar) {
  // the wheel scrolls the tabs while the pointer is over them: a two finger swipe on a touchpad, or a
  // mouse wheel like a window that only scrolls sideways. Owning the wheel keeps the window behind still
  if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(tab_bar->BarRect.Min, tab_bar->BarRect.Max)) {
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
}

struct ScrollableTabBar { ImGuiTabBar *tab_bar; bool overflowing; };
std::vector<ScrollableTabBar> scrollable_tab_bars;
}  // namespace

bool beginScrollableTabBar(const char *str_id, ImGuiTabBarFlags flags) {
  // the buttons take their room from the bar when the tabs overflowed last frame
  ImGuiWindow *window = ImGui::GetCurrentWindow();
  ImGuiTabBar *prev_tab_bar = ImGui::TabBarFindByID(window->GetID(str_id));
  const bool overflowing = prev_tab_bar && prev_tab_bar->WidthAllTabsIdeal > window->WorkRect.GetWidth() + 1.0f;
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

  scrollWithWheel(bar.tab_bar);
}

void scrollableDockSpace(ImGuiID id, const ImVec2 &size) {
  ImGuiWindow *parent = ImGui::GetCurrentWindow();
  const ImVec2 cursor = ImGui::GetCursorScreenPos();
  const bool is_set_pos = parent->DC.IsSetPos;
  std::vector<ImGuiID> overflowing;
  auto prepare = [&](auto &&self, ImGuiDockNode *node) -> void {
    if (!node) return;
    if (!node->IsLeafNode()) {
      self(self, node->ChildNodes[0]);
      self(self, node->ChildNodes[1]);
      return;
    }
    auto *bar = node->TabBar;
    if (!bar || !bar->ID || !node->HostWindow || node->IsHiddenTabBar() || node->IsNoTabBar()) return;
    const auto &style = ImGui::GetStyle();
    // Reserve the native group's close/menu buttons, then the shared chevrons.
    const float padding = style.WindowBorderSize + style.FramePadding.x;
    ImRect rect(node->Pos, ImVec2(node->Pos.x + node->Size.x, node->Pos.y + ImGui::GetFrameHeight()));
    rect.Min.x += padding;
    rect.Max.x -= padding;
    const float button_width = ImGui::GetFontSize() + style.ItemInnerSpacing.x;
    if (node->HasCloseButton) rect.Max.x -= button_width;
    if (node->HasWindowMenuButton && style.WindowMenuButtonPosition == ImGuiDir_Left) rect.Min.x += button_width;
    if (node->HasWindowMenuButton && style.WindowMenuButtonPosition == ImGuiDir_Right) rect.Max.x -= button_width;
    if (bar->WidthAllTabsIdeal > rect.GetWidth() + 1.0f) {
      rect.Max.x -= scrollButtonsWidth();
      overflowing.push_back(node->ID);
    }
    bar->BarRect = rect;
    bar->Flags = (bar->Flags & ~ImGuiTabBarFlags_FittingPolicyMask_) |
                 ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_NoTabListScrollingButtons;
    // Amend before DockSpace submits its tabs. ImGui's append path retains this
    // layout and flags while preserving native tab dragging, closing and focus.
    ImGui::PushOverrideID(node->ID);
    if (ImGui::BeginTabBarEx(bar, rect, bar->Flags)) ImGui::EndTabBar();
    ImGui::PopID();
  };
  prepare(prepare, ImGui::DockBuilderGetNode(id));
  parent->DC.CursorPos = cursor;
  parent->DC.IsSetPos = is_set_pos;
  ImGui::DockSpace(id, size);
  const ImVec2 after = ImGui::GetCursorScreenPos();
  const bool after_is_set_pos = parent->DC.IsSetPos;
  for (auto node_id : overflowing) {
    auto *node = ImGui::DockBuilderGetNode(node_id);
    if (node && ImGui::DockNodeBeginAmendTabBar(node)) {
      drawScrollButtons(node->TabBar);
      scrollWithWheel(node->TabBar);
      ImGui::DockNodeEndAmendTabBar();
    }
  }
  parent->DC.CursorPos = after;
  parent->DC.IsSetPos = after_is_set_pos;
}
