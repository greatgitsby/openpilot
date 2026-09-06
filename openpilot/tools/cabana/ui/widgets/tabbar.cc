#include "tools/cabana/ui/widgets/tabbar.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <utility>
#include <vector>

namespace {
// one size everywhere: half again as wide as imgui's own tab bar arrows (font size - 2), a frame tall
ImVec2 scrollButtonSize() {
  return ImVec2((ImGui::GetFontSize() - 2.0f) * 1.5f, ImGui::GetFrameHeight());
}

// the room a tab bar inside a window gives up for the pair: item spacing away from the tabs, no gap between
float scrollButtonsWidth() {
  return scrollButtonSize().x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
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
  drawScrollButtons(tab_bar, ImVec2(tab_bar->BarRect.Max.x + ImGui::GetStyle().ItemSpacing.x, tab_bar->BarRect.Min.y), scrollButtonSize(), 0.0f);
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

}  // namespace


int TabBar::addTab(const std::string &text, const std::string &window_id) {
  const int id = next_id_++;
  tabs_.push_back({text, 0, id, {}, {}, window_id.empty() ? std::to_string(id) : window_id});
  int index = count() - 1;
  if (current_index_ == -1) {  // the first tab is current
    current_index_ = index;
    select_current_ = true;
    currentChanged(index);
  }
  return index;
}

void TabBar::setCurrentIndex(int index) {
  if (index == current_index_ || index < -1 || index >= count()) return;
  current_index_ = index;
  select_current_ = true;
  currentChanged(index);
}

int TabBar::tabAt(const ImVec2 &pos) const {
  for (int i = 0; i < count(); ++i) {
    if (tabs_[i].rect.Contains(pos)) return i;
  }
  return -1;
}

void TabBar::removeTab(int index) {
  tabs_.erase(tabs_.begin() + index);
  if (index == current_index_) {
    // select the tab that moved into this index, else the one to the left
    current_index_ = count() ? std::min(index, count() - 1) : -1;
    select_current_ = true;
    currentChanged(current_index_);
  } else if (index < current_index_) {
    --current_index_;
  }
}

void TabBar::clear() {
  tabs_.clear();
  current_index_ = -1;
  select_current_ = false;
}

void TabBar::moveTab(int from, int to) {
  if (from == to || from < 0 || from >= count() || to < 0 || to >= count()) return;
  const int current_id = current_index_ >= 0 ? tabs_[current_index_].id : -1;
  Tab tab = std::move(tabs_[from]);
  tabs_.erase(tabs_.begin() + from);
  tabs_.insert(tabs_.begin() + to, std::move(tab));
  for (int i = 0; i < count(); ++i) {
    if (tabs_[i].id == current_id) current_index_ = i;
  }
  select_current_ = true;  // imgui orders the tabs as submitted only when a tab is (re)selected
}

void TabBar::setDockable(bool dockable, const std::string &window_id_prefix) {
  dockable_ = dockable;
  window_id_prefix_ = window_id_prefix;
}

std::string TabBar::windowName(int index) const {
  return tabs_[index].text + "###" + window_id_prefix_ + tabs_[index].window_id;
}

std::vector<std::string> TabBar::windowNames() const {
  std::vector<std::string> names;
  for (int i = 0; i < count(); ++i) names.push_back(windowName(i));
  return names;
}

// the node of the current tab's window, else of any docked tab, else of a tab of a past session (the ini keeps
// the window settings), else the default
ImGuiID TabBar::dockNodeForNewTabs() const {
  auto node_of = [](const std::string &name) -> ImGuiID {
    if (const ImGuiWindow *w = ImGui::FindWindowByName(name.c_str())) return w->DockId;
    if (const ImGuiWindowSettings *s = ImGui::FindWindowSettingsByID(ImHashStr(name.c_str()))) return s->DockId;
    return 0;
  };
  if (current_index_ >= 0 && tabs_[current_index_].docked) {
    if (ImGuiID id = node_of(windowName(current_index_))) return id;
  }
  for (int i = 0; i < count(); ++i) {
    if (ImGuiID id = node_of(windowName(i))) return id;
  }
  return default_dock_node_ ? default_dock_node_() : 0;
}

void TabBar::draw(const Content &content) {
  dockable_ ? drawDocked(content) : drawInline(content);
}

void TabBar::drawDocked(const Content &content) {
  const ImGuiID dock_id = dockNodeForNewTabs();
  const bool select_current = std::exchange(select_current_, false);
  int close_index = -1;
  for (int i = 0; i < count(); ++i) {
    Tab &tab = tabs_[i];
    if (!tab.docked) {
      // a new tab joins the others (or floats when they are floating/hidden) and comes to the front
      if (dock_id) ImGui::SetNextWindowDockID(dock_id, ImGuiCond_Once);
      ImGui::SetNextWindowFocus();
      tab.docked = true;
    } else if (select_current && i == current_index_) {
      ImGui::SetNextWindowFocus();
    }
    // the tab windows float out like the dialogs, and their dock nodes have no window menu button: its
    // only entry hides the tab bar, and with it the title and the close button
    ImGuiWindowClass window_class;
    window_class.ViewportFlagsOverrideSet = ImGuiViewportFlags_NoAutoMerge;
    window_class.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoWindowMenuButton;
    ImGui::SetNextWindowClass(&window_class);

    bool open = true;
    const std::string name = windowName(i);
    const bool visible = ImGui::Begin(name.c_str(), tabs_closable_ ? &open : nullptr, window_flags_);
    ImGuiWindow *window = ImGui::GetCurrentWindow();
    // the tab's rect is its item in the dock node's tab bar, else the window itself
    tab.rect = window->Rect();
    if (window->DockNode && window->DockNode->TabBar) {
      ImGuiTabBar *tab_bar = window->DockNode->TabBar;
      if (const ImGuiTabItem *item = ImGui::TabBarFindTabByID(tab_bar, window->TabId)) {
        const float x = tab_bar->BarRect.Min.x + item->Offset - tab_bar->ScrollingAnim;
        tab.rect = ImRect(x, tab_bar->BarRect.Min.y, x + item->Width, tab_bar->BarRect.Max.y);
      }
    }
    // focusing a tab (clicking it, or its window) makes it current
    if (!select_current && i != current_index_ && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
      current_index_ = i;
      currentChanged(i);
    }
    if (content) content(i, visible);
    ImGui::End();
    if (!open) close_index = i;
  }
  if (close_index >= 0) tabCloseRequested(close_index);
}

void TabBar::drawInline(const Content &content) {
  if (auto_hide_ && count() < 2) {  // auto hidden with fewer than two tabs
    if (content) {
      for (int i = 0; i < count(); ++i) content(i, i == current_index_);
    }
    return;
  }
  ImGui::PushID(this);
  // no default tooltip, the tabs carry their own
  if (!beginScrollableTabBar("##tabbar", ImGuiTabBarFlags_NoTooltip)) {
    ImGui::PopID();
    return;
  }
  // every tab gets a close button, not only the hovered/selected one
  ImGuiStyle &style = ImGui::GetStyle();
  const float close_button_min_width = tabs_closable_ ? std::exchange(style.TabCloseButtonMinWidthUnselected, -1.0f) : 0.0f;
  // setCurrentIndex requests are applied on the next frame
  const bool select_current = std::exchange(select_current_, false);
  int close_index = -1;
  for (int i = 0; i < count(); ++i) {
    bool open = true;
    const std::string label = tabs_[i].text + "###tab" + std::to_string(tabs_[i].id);
    const ImGuiTabItemFlags flags = (select_current && i == current_index_) ? ImGuiTabItemFlags_SetSelected : 0;
    if (ImGui::BeginTabItem(label.c_str(), tabs_closable_ ? &open : nullptr, flags)) {
      // a programmatic selection takes effect on the next frame, ignore the old tab until then
      if (!select_current && i != current_index_) {
        current_index_ = i;
        currentChanged(i);
      }
      ImGui::EndTabItem();
    }
    tabs_[i].rect = ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
    if (!tabs_[i].tooltip.empty()) ImGui::SetItemTooltip("%s", tabs_[i].tooltip.c_str());
    tabContextMenu(i);
    if (!open) close_index = i;
  }
  if (tabs_closable_) style.TabCloseButtonMinWidthUnselected = close_button_min_width;
  endScrollableTabBar();
  ImGui::PopID();
  if (content) {
    for (int i = 0; i < count(); ++i) content(i, i == current_index_);
  }
  if (close_index >= 0) tabCloseRequested(close_index);
}

// imgui lays out a dock node's tab bar with its own arrows (TabBarScrollingButtons) when the tabs overflow: two
// (font size - 2) wide buttons at the right end of the bar, and the bar rect shrinks by their width plus one.
// They are painted over with the title bar background and the chevron buttons are drawn in their place, in a
// small input-taking window on top of the host, so the clicks land on ours
void TabBar::styleDockTabBars() {
  ImGuiContext &g = *ImGui::GetCurrentContext();
  const float arrows_width = (g.FontSize - 2.0f) * 2.0f;  // what imgui reserved
  // wider than imgui's arrows: the extra room is taken from the left, over the end of the tab strip
  const ImVec2 button_size = scrollButtonSize();
  const float buttons_width = button_size.x * 2.0f;
  for (int n = 0; n < g.DockContext.Nodes.Data.Size; ++n) {
    ImGuiDockNode *node = (ImGuiDockNode *)g.DockContext.Nodes.Data[n].val_p;
    if (!node || !node->TabBar || !node->HostWindow || !node->IsVisible || node->IsHiddenTabBar() || node->IsNoTabBar()) continue;
    ImGuiTabBar *tab_bar = node->TabBar;
    if (tab_bar->CurrFrameVisible != g.FrameCount && tab_bar->PrevFrameVisible != g.FrameCount) continue;
    // the bar rect is already reduced when the arrows are shown, so this is "ideal > the full bar width"
    if (tab_bar->Tabs.Size < 2 || tab_bar->WidthAllTabsIdeal <= tab_bar->BarRect.GetWidth() + arrows_width + 1.0f) continue;

    const ImVec2 pos(tab_bar->BarRect.Max.x + 1.0f + arrows_width - buttons_width, tab_bar->BarRect.Min.y);
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

