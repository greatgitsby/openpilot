#pragma once

#include <functional>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"

#include "tools/cabana/core/observable.h"

// the one tab bar of the app: every tab row (charts, cameras, message views, dialogs) is a TabBar so they all
// look and scroll the same. The tabs scroll with a pair of chevron buttons at the right end when they overflow,
// in place of imgui's small arrows, and the wheel scrolls them while the pointer is over the bar.
// Tabs are closable when setTabsClosable(true).
//
// setDockable(true) makes every tab its own dock window instead of a row inside the caller's window: the tabs
// share a dock node (so they look like a tab row) until one is dragged out into its own panel or os window. The
// content of each tab is then drawn by the callback given to draw(), inside the tab's window.
class TabBar {
public:
  using Content = std::function<void(int index, bool visible)>;  // visible: draw the tab's content now

  TabBar() = default;
  // restyles the tab bars imgui draws itself on the dock nodes to match: call once per frame after all the
  // docked windows are drawn
  static void styleDockTabBars();

  // window_id: the stable part of the tab's window name in dockable mode (the tab's number when empty)
  int addTab(const std::string &text, const std::string &window_id = {});
  int count() const { return (int)tabs_.size(); }
  void setTabText(int index, const std::string &text) { if (index >= 0 && index < count()) tabs_[index].text = text; }
  const std::string &tabText(int index) const { return tabs_[index].text; }
  void setTabToolTip(int index, const std::string &tip) { if (index >= 0 && index < count()) tabs_[index].tooltip = tip; }
  void setTabData(int index, int data) { if (index >= 0 && index < count()) tabs_[index].data = data; }
  int tabData(int index) const { return index >= 0 && index < count() ? tabs_[index].data : 0; }
  int currentIndex() const { return current_index_; }
  void setCurrentIndex(int index);
  int tabAt(const ImVec2 &pos) const;  // -1 when no tab covers pos
  void removeTab(int index);
  void clear();  // removes every tab, no currentChanged
  void moveTab(int from, int to);
  void setAutoHide(bool hide) { auto_hide_ = hide; }
  void setTabsClosable(bool closable) { tabs_closable_ = closable; }  // off by default
  // dockable: each tab is a dock window named "text###<window_id_prefix><window_id>"
  void setDockable(bool dockable, const std::string &window_id_prefix = {});
  bool dockable() const { return dockable_; }
  // the dock node a new tab goes to when no other tab of this bar is docked anywhere (dockable mode)
  void setDefaultDockNode(std::function<ImGuiID()> fn) { default_dock_node_ = std::move(fn); }
  void setWindowFlags(ImGuiWindowFlags flags) { window_flags_ = flags; }  // the tab windows (dockable mode)
  std::string windowName(int index) const;  // dockable mode
  std::vector<std::string> windowNames() const;
  // inline: the tab row, then content(i, i == current) for every tab. dockable: content(i, open) inside each
  // tab's window
  void draw(const Content &content = {});

  Observable<int> currentChanged;
  Observable<int> tabCloseRequested;
  Observable<int> tabContextMenu;  // emitted while drawing, right after the tab: open a context popup from it

private:
  struct Tab { std::string text; int data = 0; int id = 0; std::string tooltip; ImRect rect; std::string window_id; bool docked = false; };
  void drawInline(const Content &content);
  void drawDocked(const Content &content);
  ImGuiID dockNodeForNewTabs() const;
  std::vector<Tab> tabs_;
  int current_index_ = -1;
  int next_id_ = 0;
  bool select_current_ = false;  // programmatic current change, applied at the next draw()
  bool auto_hide_ = false;
  bool tabs_closable_ = false;
  bool dockable_ = false;
  std::string window_id_prefix_;
  std::function<ImGuiID()> default_dock_node_;
  ImGuiWindowFlags window_flags_ = 0;
};
