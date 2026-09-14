#pragma once

#include <functional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "implot.h"
#include "tools/cabana/analysis/fields.h"
#include "tools/cabana/analysis/session.h"
#include "tools/cabana/analysis/transforms.h"
#include "json11/json11.hpp"

#include "tools/cabana/ui/chart/tiplabel.h"
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
    MessageId msg_id;
    const cabana::Signal *sig = nullptr;
    std::string name;
    std::string source;
    std::shared_ptr<const cabana::Samples> snapshot;
    CabanaColor color;
    bool visible = true;
    std::string alias;
    cabana::TransformSettings transform;
    std::shared_ptr<const cabana::DisplaySamples> data = std::make_shared<const cabana::DisplaySamples>();
    ImPlotPoint track_pt{};
    bool usesCanFormatting() const { return sig && transform.type == cabana::Transform::None && transform.scale == 1 && transform.offset == 0; }
    std::string label() const { return (alias.empty() ? name : alias) + (snapshot ? "" : " (missing)"); }
    double min = 0;
    double max = 0;
  };

  ChartView(const std::pair<double, double> &x_range, ChartsWidget *parent);
  void addSignal(const MessageId &msg_id, const cabana::Signal *sig);
  void addSource(const std::string &source);
  void addBinding(const MessageId &msg_id, const std::string &name);
  void resolveBindings();
  json11::Json definition() const;
  void restoreDefinition(const json11::Json &definition);
  const std::string &paneId() const { return pane_id_; }
  void setPaneId(const std::string &id) { pane_id_ = id; }
  SeriesType seriesType() const { return series_type_; }
  bool hasSignal(const MessageId &msg_id, const cabana::Signal *sig) const;
  void updateSeries(const cabana::Signal *sig = nullptr, const MessageEventsMap *msg_new_events = nullptr);
  void updatePlot(double cur, double min, double max);
  void setSeriesType(SeriesType type) { series_type_ = type; }
  void showTip(double sec);
  void hideTip();
  void draw(const ImVec2 &size);
  std::string windowName() const { return (title_.empty() ? "Chart" : title_) + "###Chart/" + pane_id_; }
  void removeIf(std::function<bool(const SigItem &)> predicate);
  void takeSignalsFrom(ChartView *source);
  // every signal but the first, with its original color, for a split into one chart per signal
  std::vector<SigItem> takeExtraSignals();
  void adoptSignal(SigItem s);
  void setDropHighlight(bool highlight) { can_drop_ = highlight; }
  const std::vector<SigItem> &signals() const { return sigs_; }
  const ImRect &rect() const { return layout_.rect; }  // the whole chart widget, screen coordinates
  bool plotHovered() const { return layout_.plot_hovered; }
  double secondsAtPoint(const ImVec2 &pt) const {
    return x_min_ + (pt.x - layout_.plot_area.Min.x) * (x_max_ - x_min_) / std::max(layout_.plot_area.GetWidth(), 1.0f);
  }

private:
  using PointIter = cabana::Samples::const_iterator;

  void signalUpdated(const cabana::Signal *sig);
  void manageSignals();
  void msgRemoved(MessageId id) { resolveBindings(); }
  void signalRemoved(const cabana::Signal *sig);

  void createToolButtons();
  void drawContextMenu();
  void handleMousePress();
  void handleMouseMove();
  void handleMouseRelease();
  void updateLayout();
  void updateAxisY();
  void paint();
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
  const cabana::Sample *lastPointBefore(const SigItem &s, double sec) const;
  // the samples inside [x_min_, x_max_)
  std::pair<PointIter, PointIter> visibleRange(const cabana::Samples &points) const;
  inline void clearTrackPoints() { for (auto &s : sigs_) s.track_pt = {}; }
  inline float xPos(double sec) const { return layout_.plot_area.Min.x + (sec - x_min_) / (x_max_ - x_min_) * layout_.plot_area.GetWidth(); }
  inline float yPos(double val) const { return layout_.plot_area.Max.y - (val - y_min_) / (y_max_ - y_min_) * layout_.plot_area.GetHeight(); }

  // layout
  struct Layout {
    ImRect rect;  // the whole chart widget, screen coordinates
    ImRect visible_rect;  // cached in the owning pane for updates between frames
    ImRect content_rect;  // the same inset on all four sides, including during a drag
    ImRect plot_area;
    ImRect move_icon_rect;
    ImRect close_btn_rect;
    ImRect manage_btn_rect;
    std::vector<ImRect> legend_rects;
    float header_bottom = 0;
    bool plot_hovered = false;
    bool compact_header = false;
  } layout_;
  // axes
  double x_min_;
  double x_max_;
  double y_min_ = 0;
  double y_max_ = 1;
  int y_tick_count_ = 3;
  int y_precision_ = 1;
  std::string y_unit_;
  // interaction
  enum class MouseMode { None, Rubber, Scrub };
  MouseMode mouse_mode_ = MouseMode::None;
  ImVec2 press_pos_;
  ImRect rubber_rect_;
  bool resume_after_scrub_ = false;
  std::string pane_id_;
  std::string title_;
  json11::Json saved_range_;
  std::optional<double> y_lower_, y_upper_;
  ImGuiID context_menu_id_ = 0;

  TipLabel tip_label_;
  std::vector<SigItem> sigs_;
  double cur_sec_ = 0;
  SeriesType series_type_ = SeriesType::Line;
  bool can_drop_ = false;
  double tooltip_x_ = -1;
  ChartsWidget *charts_widget_;
  Connections connections_;
};
