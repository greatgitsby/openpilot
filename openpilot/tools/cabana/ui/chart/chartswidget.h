#pragma once

#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"

#include "tools/cabana/ui/chart/signalselector.h"
#include "tools/cabana/ui/chart/signaltree.h"
#include "tools/cabana/commands.h"
#include "tools/cabana/ui/chart/zoomcommand.h"
#include "tools/cabana/core/source.h"
#include "tools/cabana/analysis/equations.h"
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

class ChartView;
class ChartManager;

class ChartManager {
public:
  ChartManager();
  ~ChartManager();  // out of line: the header users only see a forward declared ChartView
  void draw();  // independent dockable chart windows
  void newChart();
  std::vector<std::string> windowNames() const;
  void syncSources();
  void removeSource(const std::string &id);
  void drawAnalysisMenu();
  std::function<void(double)> seekRequested;
  std::function<void(bool)> pauseRequested;
  void requestSeek(double route_seconds) { if (seekRequested) seekRequested(route_seconds); else can->seekTo(route_seconds); }
  void requestPause(bool paused) { if (pauseRequested) pauseRequested(paused); else can->pause(paused); }
  size_t chartCount() const { return charts_.size(); }
  std::shared_ptr<const cabana::Samples> fieldsSnapshot(const std::string &path, const std::string &source_id = {}) const;
  std::string serializeLayout() const;
  enum class LayoutStatus { Restored, MissingCan, Failed };
  LayoutStatus restoreLayout(const std::string &contents, bool defer_missing_can = false);
  LayoutStatus openLayout(const std::string &path, bool defer_missing_can = false);
  void showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge);
  inline bool hasSignal(const MessageId &id, const cabana::Signal *sig) { return findChart(id, sig) != nullptr; }
  std::string whatsThis() const;

  void removeAll();

  void drawSignalBrowser();
  Observable<> showLogMessages;
  Observable<> chartAdded;
  Observable<> seriesChanged;

private:
  ChartView *createChart(int pos = 0, bool restoring = false);
  void removeChart(ChartView *chart);
  void splitChart(ChartView *chart);
  ImRect chartVisibleRect(ChartView *chart);
  void fieldsChanged();
  void rebuildSignalBrowser();
  void pollFields();
  void eventsMerged(const MessageEventsMap &new_events);
  void updateState();
  void zoomReset();
  void openFunctionEditor(const cabana::Equation *equation = nullptr);
  void drawFunctionEditor();
  void exportCsv();
  void fitTimeRange();
  void setMaxChartRange(int value);
  void settingChanged();
  void showValueTip(double sec);
  ChartView *findChart(const MessageId &id, const cabana::Signal *sig);
  // draws the selector until closed, then runs `accepted` (unless `owner` was removed)
  void execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted);
  std::vector<ChartView *> currentCharts() const;

  LogSlider range_slider_{1000};
  UndoStack zoom_undo_stack_;

  std::vector<std::unique_ptr<ChartView>> charts_;
  std::vector<cabana::Equation> equations_;
  cabana::Equation function_draft_;
  std::string function_original_name_, function_filter_;
  std::vector<std::string> function_sources_;
  bool function_editor_open_ = false, function_editor_show_ = false, function_plot_ = true;
  std::unordered_map<std::string, cabana::FieldsSnapshot> source_calculated_;
  std::unordered_set<std::string> dirty_sources_;
  struct EquationResult {
    cabana::FieldsSnapshot values;
    std::string errors;
    size_t revision = 0;
    std::string source_id;
    std::weak_ptr<bool> source_alive;
  };
  std::shared_ptr<EquationResult> equation_result_;
  std::future<void> equation_task_;
  size_t equation_revision_ = 0;
  std::string equation_errors_;
  int max_chart_range_ = 0;
  std::pair<double, double> display_range_;
  uint64_t next_chart_id_ = 1;
  ChartView *active_chart_ = nullptr;
  std::unordered_map<std::string, Connections> source_connections_;
  std::unordered_map<std::string, double> source_offsets_;
  struct BrowserState {
    std::string filter;
    size_t field_count = 0;
    chart::SignalTree tree;
    bool dirty = true;
    std::unordered_set<std::string> expanded, search_expanded;
  };
  std::unordered_map<std::string, BrowserState> browsers_;
  std::string function_source_id_;
  bool value_tip_visible_ = false;
  bool any_plot_hovered_ = false;
  std::vector<std::unique_ptr<ChartView>> deleted_charts_;  // freed at the start of the next draw()
  std::unique_ptr<SignalSelector> signal_selector_;
  ChartView *signal_selector_owner_ = nullptr;
  std::function<void(SignalSelector &)> signal_selector_accepted_;
  Connections connections_;
  friend class ChartView;

};

// Compatibility for route-specific browser and inspector clients.
using ChartsWidget = ChartManager;
