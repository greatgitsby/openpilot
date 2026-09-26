#pragma once

#include <functional>
#include <future>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"

#include "tools/cabana/ui/chart/signalselector.h"
#include "tools/cabana/ui/chart/signaltree.h"
#include "tools/cabana/ui/chart/zoomcommand.h"
#include "tools/cabana/analysis/equations.h"
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

class ChartView;

// Every chart is its own dockable window. A chart can plot CAN signals, log fields and functions of any source.
class ChartsWidget {
public:
  ChartsWidget();
  ~ChartsWidget();  // out of line: the header users only see a forward declared ChartView
  void draw();  // the chart windows
  void drawSignalBrowser();  // the log fields and functions of the current source
  void drawAnalysisMenu();
  ChartView *newChart();
  size_t chartCount() const { return charts_.size(); }
  std::vector<std::string> windowNames() const;
  void showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge);
  inline bool hasSignal(const MessageId &id, const cabana::Signal *sig) { return findChart(id, sig) != nullptr; }
  void removeSource(const std::string &id);
  void removeAll();
  std::string serializeLayout() const;
  bool restoreLayout(const std::string &contents);
  bool openLayout(const std::string &path);

  std::function<void(double)> seekRequested;
  std::function<void(bool)> pauseRequested;
  Observable<> showLogMessages;
  Observable<> seriesChanged;

private:
  std::string newChartId();
  void removeChart(ChartView *chart);
  void splitChart(ChartView *chart);
  ChartView *findChart(const MessageId &id, const cabana::Signal *sig);
  void syncSources();
  void updateState();
  void zoomReset();
  void fitTimeRange();
  void settingChanged();
  void showValueTip(double sec);
  void exportCsv();
  // draws the selector until closed, then runs `accepted` (unless `owner` was removed)
  void execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted);

  // log fields and functions
  std::shared_ptr<const cabana::Samples> fieldsSnapshot(const std::string &path, const std::string &source_id) const;
  std::string equationError(const std::string &source_id, const std::string &name) const;
  void fieldsChanged(const std::string &source_id);
  void refreshFields(const std::string &source_id, bool functions_only);
  void equationsChanged();
  void pollEquations();
  void openFunctionEditor(const cabana::Equation *equation = nullptr);
  void drawFunctionEditor();

  LogSlider range_slider_{1000};
  UndoStack zoom_undo_stack_;
  int max_chart_range_ = 0;
  std::pair<double, double> display_range_;

  std::vector<std::unique_ptr<ChartView>> charts_;
  std::vector<std::unique_ptr<ChartView>> deleted_charts_;  // freed at the start of the next draw()
  uint64_t next_chart_id_ = 1;
  ChartView *active_chart_ = nullptr;
  bool value_tip_visible_ = false;
  std::unique_ptr<SignalSelector> signal_selector_;
  ChartView *signal_selector_owner_ = nullptr;
  std::function<void(SignalSelector &)> signal_selector_accepted_;
  std::unordered_map<std::string, Connections> source_connections_;
  std::unordered_map<std::string, double> source_offsets_;

  // functions are evaluated in the background, for one source at a time
  std::vector<cabana::Equation> equations_;
  struct Calculated {
    cabana::FieldsSnapshot values;
    std::map<std::string, std::string> errors;  // by function name
  };
  std::unordered_map<std::string, Calculated> calculated_;  // by source
  std::unordered_set<std::string> dirty_sources_;
  struct EquationResult {
    Calculated calculated;
    std::string source_id;
    std::weak_ptr<bool> source_alive;
    size_t revision = 0;
  };
  std::shared_ptr<EquationResult> equation_result_;
  std::future<void> equation_task_;
  size_t equation_revision_ = 0;

  // the function editor
  cabana::Equation function_draft_;
  std::string function_original_name_, function_filter_, function_source_id_;
  std::vector<std::string> function_sources_;
  bool function_editor_open_ = false, function_editor_show_ = false, function_plot_ = true;

  struct BrowserState {
    std::string filter;
    size_t field_count = 0;
    chart::SignalTree tree;
    bool dirty = true;
    std::unordered_set<std::string> expanded, search_expanded;
  };
  std::unordered_map<std::string, BrowserState> browsers_;  // by source
  Connections connections_;
  friend class ChartView;
};
