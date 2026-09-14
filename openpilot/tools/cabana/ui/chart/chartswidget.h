#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "imgui.h"
#include "tools/cabana/ui/util.h"
#include "json11/json11.hpp"
#include "tools/cabana/analysis/session.h"
#include "tools/cabana/ui/dialogs/functioneditor.h"
#include "tools/cabana/ui/widgets/seriesbrowser.h"
#include "imgui_internal.h"

#include "tools/cabana/ui/chart/signalselector.h"
#include "tools/cabana/ui/widgets/tabbar.h"
#include "tools/cabana/commands.h"
#include "tools/cabana/dbc/dbcmanager.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/utils/util.h"


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

namespace docking { class Workspace; }
class ChartView;
class ChartsWidget;

class ChartsWidget {
public:
  explicit ChartsWidget(cabana::AnalysisSession &session);
  cabana::AnalysisSession &session;
  ~ChartsWidget();  // out of line: the header users only see a forward declared ChartView
  void draw();  // workspace controls
  void drawPanes(docking::Workspace &workspace);
  void drawMenus();
  void drawPageControls(const std::vector<ToolbarItem> &workspace_items = {});
  std::string addPlot();
  bool widgetVisible(const std::string &id) const;
  void setWidgetVisible(const std::string &id, bool visible);
  json11::Json workspace() const;
  uint64_t documentRevision() const { return document_revision_; }
  bool restoreWorkspace(const json11::Json &doc, bool restore_range = true);
  std::string activePageId() const { return page_ids_.at(tabbar_.tabData(tabbar_.currentIndex())); }
  std::vector<std::string> pageIds() const;
  json11::Json pageLayout(const std::string &id) const;
  void setPageLayout(const std::string &id, const json11::Json &layout) { page_layouts_[id] = layout; }
  std::vector<std::string> paneWindows() const;
  size_t chartCount() const { return charts_.size(); }
  void showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge);
  inline bool hasSignal(const MessageId &id, const cabana::Signal *sig) { return findChart(id, sig) != nullptr; }
  std::vector<std::string> serializeChartIds() const;
  void restoreChartsFromIds(const std::vector<std::string> &chart_ids);
  std::string whatsThis() const;

  void removeAll(bool reset_range = true);

  Observable<> seriesChanged;
  Observable<double> showTip;

private:
  void newChart();
  void openWorkspace(const std::string &path);
  void editEquation(const std::string &id);
  ChartView *createChart(int pos = 0);
  void removeChart(ChartView *chart);
  void splitChart(ChartView *chart);
  void eventsMerged(const MessageEventsMap &new_events);
  void updateState();
  void zoomReset();
  void drawToolBar(std::vector<ToolbarItem> items);
  void setMaxChartRange(int value);
  void settingChanged();
  void showValueTip(double sec);
  void newTab();
  void removeTab(int index);
  inline std::vector<ChartView *> &currentCharts() { return tab_charts_[tabbar_.tabData(tabbar_.currentIndex())]; }
  ChartView *findChart(const MessageId &id, const cabana::Signal *sig);
  // draws the selector until closed, then runs `accepted` (unless `owner` was removed)
  void execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted);

  uint64_t document_revision_ = 0;
  LogSlider range_slider_{1000};
  std::map<std::string, cabana::Equation> equations_;
  FunctionEditor function_editor_;
  SeriesBrowser browser_;

  UndoStack zoom_undo_stack_;

  std::vector<std::unique_ptr<ChartView>> charts_;
  std::unordered_map<int, std::vector<ChartView *>> tab_charts_;
  TabBar tabbar_;
  std::unordered_map<int, std::string> page_ids_;
  std::unordered_map<std::string, json11::Json> page_layouts_;
  std::unordered_map<std::string, std::set<std::string>> page_widgets_;
  int max_chart_range_ = 0;
  std::pair<double, double> display_range_;
  bool value_tip_visible_ = false;
  bool any_plot_hovered_ = false;
  std::string dragged_chart_id_;
  int merge_drop_frames_ = 0;
  std::vector<std::unique_ptr<ChartView>> deleted_charts_;  // freed at the start of the next draw()
  std::unique_ptr<SignalSelector> signal_selector_;
  ChartView *signal_selector_owner_ = nullptr;
  std::function<void(SignalSelector &)> signal_selector_accepted_;
  Connections connections_;
  friend class ChartView;
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
