#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"

#include "tools/cabana/ui/chart/signalselector.h"
#include "tools/cabana/ui/widgets/tabbar.h"
#include "tools/cabana/commands.h"
#include "tools/cabana/dbc/dbcmanager.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/utils/util.h"

const int CHART_MIN_WIDTH = 300;

// a slider whose value is mapped onto a log10 scale
class LogSlider {
public:
  LogSlider(double factor) : scale_(factor) {}

  void setRange(double min, double max) {
    scale_.setRange(min, max);
    min_ = min;
    max_ = max;
    setValue(pos_);  // the raw position is re-mapped as a value
  }
  int value() const { return scale_.value(pos_, minimum(), maximum()); }
  void setValue(int v) { pos_ = scale_.position(v, minimum(), maximum()); }
  int minimum() const { return min_; }
  int maximum() const { return max_; }
  bool draw(const char *label, float width);

private:
  LogScale scale_;
  int min_ = 0;
  int max_ = 1;
  int pos_ = 0;
};

class ChartView;
class ChartsWidget;

// the grid of one tab's charts
class ChartsContainer {
public:
  ChartsContainer(ChartsWidget *parent, int tab_id) : charts_widget_(parent), tab_id_(tab_id) {}
  void setDropIndicator(const ImVec2 &pt) { drop_indicator_pos_ = pt; }
  void draw();  // grid layout of the tab's charts
  ChartView *getDropAfter(const ImVec2 &pos) const;
  ChartView *childAt(const ImVec2 &pos) const;
  const ImRect &geometry() const { return geometry_; }  // screen coordinates
  int tabId() const { return tab_id_; }
  bool columnsSelectable() const { return columns_selectable_; }

  ImGuiWindow *scroll = nullptr;  // the scroll area child window of the last draw
  ImRect viewport;                // its inner rect

private:
  void updateLayout();
  void drawDropIndicator();
  const std::vector<ChartView *> &charts() const;

  ImRect geometry_;
  ChartsWidget *charts_widget_;
  int tab_id_;
  ImVec2 drop_indicator_pos_;
  bool columns_selectable_ = false;  // wide enough for more than one column
  int column_count_ = 1;
};

class ChartsWidget {
public:
  ChartsWidget();
  ~ChartsWidget();  // out of line: the header users only see a forward declared ChartView
  void draw();  // every tab's dock window, and the drag preview and dialogs
  TabBar &tabBar() { return tabbar_; }
  void newTab();
  std::function<void(const ImRect &)> paneDrawn;  // called with the rect of every drawn tab window
  void showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge);
  inline bool hasSignal(const MessageId &id, const cabana::Signal *sig) { return findChart(id, sig) != nullptr; }
  std::vector<std::string> serializeChartIds() const;
  void restoreChartsFromIds(const std::vector<std::string> &chart_ids);
  std::string whatsThis() const;

  void setColumnCount(int n);
  void removeAll();

  Observable<> seriesChanged;
  Observable<double> showTip;

private:
  void handleEvents();  // focus loss, the chart drag and the value tip leave
  void drawTab(int index);  // the toolbar and the chart grid of one tab, inside its window
  void newChart();
  ChartView *createChart(int pos = 0);
  void removeChart(ChartView *chart);
  void splitChart(ChartView *chart);
  ImRect chartVisibleRect(ChartView *chart);
  void eventsMerged(const MessageEventsMap &new_events);
  void updateState();
  void zoomReset();
  void startChartDrag(ChartView *chart, const ImVec2 &global_pos);
  void dragChartMove(const ImVec2 &global_pos);
  void dragChartRelease(const ImVec2 &global_pos);
  void cancelChartDrag();
  bool chartDragActive() const { return drag_.source != nullptr; }
  void startAutoScroll(const ImVec2 &global_pos);
  void stopAutoScroll();
  void doAutoScroll();
  void drawToolBar();
  void updateTabBar();
  void setMaxChartRange(int value);
  void settingChanged();
  void showValueTip(double sec);
  void removeTab(int index);
  // the tab being drawn, else the current (last focused) tab
  int currentTabId() const { return tabbar_.tabData(drawing_tab_ >= 0 ? drawing_tab_ : tabbar_.currentIndex()); }
  inline std::vector<ChartView *> &currentCharts() { return tab_charts_[currentTabId()]; }
  ChartsContainer *container(int tab_id);
  ChartsContainer *containerAt(const ImVec2 &global_pos);  // the tab whose scroll area covers the point
  ChartsContainer *containerOf(ChartView *chart);
  ChartView *findChart(const MessageId &id, const cabana::Signal *sig);
  // draws the selector until closed, then runs `accepted` (unless `owner` was removed)
  void execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted);
  void drawDragPreview();

  LogSlider range_slider_{1000};

  UndoStack zoom_undo_stack_;

  std::vector<std::unique_ptr<ChartView>> charts_;
  std::unordered_map<int, std::vector<ChartView *>> tab_charts_;
  std::unordered_map<int, std::unique_ptr<ChartsContainer>> containers_;
  TabBar tabbar_;
  int drawing_tab_ = -1;  // index of the tab whose window is being drawn
  int next_tab_id_ = 0;
  int max_chart_range_ = 0;
  std::pair<double, double> display_range_;
  int column_count_ = 1;
  ChartsContainer *drop_container_ = nullptr;  // the tab under the chart drag
  bool pane_hovered_ = false;  // any tab window hovered this frame
  struct ChartDrag {
    ChartView *source = nullptr;
    ImVec2 press_pos;  // global
    bool active = false;
  } drag_;
  // the drag preview is a 50% alpha copy of the whole chart tile, drawn in a window that takes no input
  ImVec2 drag_preview_pos_;
  ImVec2 drag_preview_size_;
  bool drag_preview_visible_ = false;
  ChartView *drop_target_ = nullptr;
  int auto_scroll_count_ = 0;
  ImVec2 auto_scroll_pos_;
  bool auto_scroll_timer_active_ = false;
  double auto_scroll_timer_next_ = 0;
  bool value_tip_visible_ = false;
  bool any_plot_hovered_ = false;
  std::vector<std::unique_ptr<ChartView>> deleted_charts_;  // freed at the start of the next draw()
  std::unique_ptr<SignalSelector> signal_selector_;
  ChartView *signal_selector_owner_ = nullptr;
  std::function<void(SignalSelector &)> signal_selector_accepted_;
  Connections connections_;
  friend class ChartView;
  friend class ChartsContainer;
};

class ZoomCommand : public UndoCommand {
public:
  ZoomCommand(std::pair<double, double> range) : range(range) {
    prev_range = can->timeRange();
  }
  void undo() override { can->setTimeRange(prev_range); }
  void redo() override { can->setTimeRange(range); }
  std::optional<std::pair<double, double>> prev_range, range;
};
