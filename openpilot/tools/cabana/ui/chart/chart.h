#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "implot.h"

#include "tools/cabana/core/source.h"
#include "tools/cabana/ui/chart/tiplabel.h"
#include "tools/cabana/ui/chart/analysis.h"
#include "tools/cabana/dbc/dbcmanager.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/utils/util.h"

enum class SeriesType {
  Line = 0,
  StepLine,
  Scatter
};
inline constexpr const char *SERIES_TYPE_NAMES[] = {"Line", "Step Line", "Scatter"};

// the message part of a legend entry, drawn after the signal name
inline std::string msgLabel(const MessageId &id) { return " " + msgName(id) + " " + id.toString(); }

class ChartsWidget;
class ChartView {
public:
  struct SigItem {
    std::string source_id;
    std::string path;  // a log field or function; empty for a CAN signal
    MessageId msg_id;
    std::string signal_name;
    const cabana::Signal *sig = nullptr;  // from the source's DBC, once it defines the signal
    CabanaColor color;
    bool visible = true;
    chart::TransformSettings transform;
    chart::TransformState transform_state;
    std::vector<ImPlotPoint> raw_vals;  // before the transform
    std::vector<ImPlotPoint> vals;
    std::vector<ImPlotPoint> step_vals;
    ImPlotPoint track_pt{};
    SegmentTree segment_tree;  // not maintained for live sources
    double min = 0;
    double max = 0;
    std::string name() const { return path.empty() ? signal_name : path; }
    std::string label() const {
      if (path.empty() || path.front() != '/') return name();
      const auto slash = path.rfind('/');
      auto leaf = path.substr(slash + 1);
      if (!leaf.empty() && leaf.find_first_not_of("0123456789") == std::string::npos && slash > 0) {
        const auto parent = path.rfind('/', slash - 1);
        return path.substr(parent + 1, slash - parent - 1) + "[" + leaf + "]";
      }
      return leaf;
    }
    std::string description() const {
      auto *source = sourceById(source_id);
      return " · " + (source ? source->source_label : source_id) + (path.empty() ? " · " + msg_id.toString() : "");
    }
  };

  ChartView(ChartsWidget *parent);
  void addSignal(const std::string &source_id, const MessageId &msg_id, const std::string &name);
  void addFields(const std::string &source_id, const std::string &path);
  bool hasSignal(const MessageId &msg_id, const cabana::Signal *sig) const;
  void updatePlot(double cur, double min, double max);
  void setSeriesType(SeriesType type) { series_type_ = type; }
  void showTip(double sec);
  void hideTip();
  void draw(float width);  // fills the window
  void removeIf(std::function<bool(const SigItem &)> predicate);
  const std::vector<SigItem> &signals() const { return sigs_; }
  bool plotHovered() const { return layout_.plot_hovered; }
  std::string windowName() const;
  double secondsAtPoint(const ImVec2 &pt) const {
    return x_min_ + (pt.x - layout_.plot_area.Min.x) * (x_max_ - x_min_) / std::max(layout_.plot_area.GetWidth(), 1.0f);
  }

  std::string widget_id, title;
  std::optional<double> limit_min, limit_max;

private:
  using PointIter = std::vector<ImPlotPoint>::const_iterator;

  void add(SigItem item);
  void resolveSignals();
  void detachSource(const std::string &id, bool dbc_only = false);
  void signalUpdated(const cabana::Signal *sig);
  void manageSignals();
  void updateSeries(const cabana::Signal *sig = nullptr, const MessageEventsMap *msg_new_events = nullptr, const std::string &source_id = {});
  void loadSeries(SigItem &s, const MessageEventsMap *new_events);
  static void buildSeries(SigItem &s, size_t begin, bool build_tree);
  void configureSignal(SigItem &s, const chart::TransformSettings &transform);
  void updateFields() { ++fields_revision_; }
  void pollFields();
  CabanaColor nextColor() const;
  std::string emptyMessage() const;
  void drawSignalAnalysis(SigItem &s);
  std::string legendName(const SigItem &s) const;
  static std::string signalUnit(const SigItem &s);
  static std::string signalValue(const SigItem &s, double value);
  void createToolButtons();
  void drawContextMenu();
  void handleMousePress();
  void handleMouseMove();
  void handleMouseRelease();
  void updateLayout();
  void updateAxisY();
  void drawStaticLayer();
  void drawAxes();
  void drawLegend();
  void drawSeries();
  void drawForeground();
  void drawSignalValue();
  void drawTimeline();
  void drawRubberBandTimeRange();
  void drawMenuActions();  // the series type / manage / split entries shared by the menu button and the context menu
  int xAxisPrecision() const;
  std::tuple<double, double, int> getNiceAxisNumbers(double min, double max, int tick_count);
  double niceNumber(double x, bool ceiling);
  CabanaColor uniqueColor(CabanaColor color, const cabana::Signal *exclude = nullptr) const;
  // the last sample at or before sec, nullptr when there is none inside the visible range
  const ImPlotPoint *lastPointBefore(const SigItem &s, double sec) const;
  // the samples inside [x_min_, x_max_)
  std::pair<PointIter, PointIter> visibleRange(const std::vector<ImPlotPoint> &points) const;
  // the plot rows across the whole chart, where the value tip is shown
  ImRect tipArea() const { return ImRect(layout_.rect.Min.x, layout_.plot_area.Min.y, layout_.rect.Max.x, layout_.plot_area.Max.y); }
  inline void clearTrackPoints() { for (auto &s : sigs_) s.track_pt = {}; }
  inline float xPos(double sec) const { return layout_.plot_area.Min.x + (sec - x_min_) / (x_max_ - x_min_) * layout_.plot_area.GetWidth(); }
  inline float yPos(double val) const { return layout_.plot_area.Max.y - (val - y_min_) / (y_max_ - y_min_) * layout_.plot_area.GetHeight(); }

  // layout
  struct Layout {
    ImRect rect;  // the whole chart widget, screen coordinates
    ImRect content_rect;  // the same inset on all four sides
    ImRect plot_area;
    ImRect add_btn_rect;
    ImRect manage_btn_rect;
    std::vector<ImRect> legend_rects;
    float header_bottom = 0;
    bool plot_hovered = false;
  } layout_;
  // axes
  double x_min_ = 0;
  double x_max_ = 1;
  double y_min_ = 0;
  double y_max_ = 1;
  int y_tick_count_ = 3;
  int y_precision_ = 1;
  std::string y_unit_;
  // interaction
  enum class MouseMode { None, Rubber, Scrub, Pan };
  MouseMode mouse_mode_ = MouseMode::None;
  ImVec2 press_pos_;
  std::pair<double, double> pan_range_;
  std::optional<std::pair<double, double>> pan_previous_;
  ImRect rubber_rect_;
  bool resume_after_scrub_ = false;
  bool focus_title_ = false;  // opens the menu with the title focused
  int pending_signal_removal_ = -1;

  TipLabel tip_label_;
  std::vector<SigItem> sigs_;
  double cur_sec_ = 0;
  SeriesType series_type_ = SeriesType::Line;
  double tooltip_x_ = -1;
  ChartsWidget *charts_widget_;
  // log fields and functions are copied and transformed in the background
  std::future<void> fields_task_;
  std::shared_ptr<std::vector<SigItem>> fields_result_;
  size_t fields_revision_ = 0, fields_task_revision_ = 0;
  friend class ChartsWidget;
};
