#define IMGUI_DEFINE_MATH_OPERATORS  // ImVec2 arithmetic, must precede imgui.h
#include "tools/cabana/ui/chart/chartswidget.h"

#include <algorithm>

#include "tools/cabana/settings.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/util.h"

bool LogSlider::draw(const char *label, float width) {
  return fusionSliderInt(label, &pos_, min_, max_, width);
}

ChartsWidget::ChartsWidget() {
  range_slider_.setRange(1, settings.max_cached_minutes * 60);
  max_chart_range_ = std::clamp(settings.chart_range, 1, settings.max_cached_minutes * 60);
  range_slider_.setValue(max_chart_range_);
  connections_.push_back(settings.changed.connect([this]() { settingChanged(); }));
}

ChartsWidget::~ChartsWidget() = default;

void ChartsWidget::syncSources() {
  for (auto *source : sources()) {
    const auto id = source->source_id;
    if (!source_connections_.count(id)) {
      auto &connections = source_connections_[id];
      auto *database = source->database();
      connections.push_back(source->fieldsChanged.connect([this, id]() { fieldsChanged(id); }));
      connections.push_back(source->eventsMerged.connect([this, id](const MessageEventsMap &events) {
        for (auto &c : charts_) c->updateSeries(nullptr, &events, id);
      }));
      connections.push_back(database->fileChanged.connect([this, id]() { for (auto &c : charts_) c->detachSource(id, true); }));
      connections.push_back(database->signalRemoved.connect([this](const cabana::Signal *sig) {
        for (auto &c : charts_) c->removeIf([=](auto &s) { return s.sig == sig; });
      }));
      connections.push_back(database->signalUpdated.connect([this](const cabana::Signal *sig) {
        for (auto &c : charts_) c->signalUpdated(sig);
      }));
      connections.push_back(database->msgRemoved.connect([this, id, database](MessageId msg) {
        for (auto &c : charts_) c->removeIf([&](const auto &s) {
          return s.source_id == id && s.path.empty() && s.msg_id.address == msg.address && !database->msg(s.msg_id);
        });
      }));
      fieldsChanged(id);
    }
    if (auto &offset = source_offsets_[id]; offset != source->timeline_offset) {
      offset = source->timeline_offset;
      for (auto &c : charts_) c->updateSeries(nullptr, nullptr, id);
      refreshFields(id, false);
    }
  }
  for (auto it = source_connections_.begin(); it != source_connections_.end();) {
    if (!sourceById(it->first)) it = source_connections_.erase(it);
    else ++it;
  }
}

std::vector<std::string> ChartsWidget::windowNames() const {
  std::vector<std::string> result;
  for (auto &c : charts_) result.push_back(c->windowName());
  return result;
}

void ChartsWidget::zoomReset() {
  can->setTimeRange(std::nullopt);
  zoom_undo_stack_.clear();
}

void ChartsWidget::showValueTip(double sec) {
  if (sec < 0 && !value_tip_visible_) return;

  value_tip_visible_ = sec >= 0;
  for (auto &c : charts_) {
    value_tip_visible_ ? c->showTip(sec) : c->hideTip();
  }
}

void ChartsWidget::updateState() {
  if (charts_.empty()) return;

  const auto &time_range = can->timeRange();
  const double cur_sec = can->currentSec();
  if (!time_range.has_value()) {
    double pos = (cur_sec - display_range_.first) / std::max<float>(1.0, max_chart_range_);
    if (pos < 0 || pos > 0.8) {
      display_range_.first = std::max(can->minSeconds(), cur_sec - max_chart_range_ * 0.1);
    }
    double max_sec = std::min(display_range_.first + max_chart_range_, can->maxSeconds());
    display_range_.first = std::max(can->minSeconds(), max_sec - max_chart_range_);
    display_range_.second = display_range_.first + max_chart_range_;
  }

  // charts show workspace time, which is the current source's route time plus its offset
  const auto &range = time_range ? *time_range : display_range_;
  for (auto &c : charts_) {
    c->updatePlot(cur_sec + can->timeline_offset, range.first + can->timeline_offset, range.second + can->timeline_offset);
  }
}

void ChartsWidget::settingChanged() {
  if (range_slider_.maximum() != settings.max_cached_minutes * 60) {
    range_slider_.setRange(1, settings.max_cached_minutes * 60);
  }
}

ChartView *ChartsWidget::findChart(const MessageId &id, const cabana::Signal *sig) {
  for (auto &c : charts_)
    if (c->hasSignal(id, sig)) return c.get();
  return nullptr;
}

std::string ChartsWidget::newChartId() {
  std::string id;
  do id = std::to_string(next_chart_id_++);
  while (std::any_of(charts_.begin(), charts_.end(), [&](const auto &c) { return c->widget_id == id; }));
  return id;
}

ChartView *ChartsWidget::newChart() {
  auto *chart = charts_.emplace_back(std::make_unique<ChartView>(this)).get();
  chart->widget_id = newChartId();
  dockNewPanel(chart->windowName());
  return active_chart_ = chart;
}

void ChartsWidget::showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge) {
  ChartView *chart = findChart(id, sig);
  if (show && !chart) {
    (merge && active_chart_ ? active_chart_ : newChart())->addSignal(can->source_id, id, sig->name);
  } else if (!show && chart) {
    chart->removeIf([&](auto &s) { return s.msg_id == id && s.sig == sig; });
  }
}

// one chart per signal: the first signal stays, the others move to new charts
void ChartsWidget::splitChart(ChartView *chart) {
  auto &sigs = chart->sigs_;
  for (size_t i = 1; i < sigs.size(); ++i) {
    auto *c = newChart();
    if (sigs[i].sig) sigs[i].color = sigs[i].sig->color;
    c->sigs_.push_back(std::move(sigs[i]));
    c->updateFields();
    c->updateAxisY();
  }
  sigs.resize(1);
  chart->updateAxisY();
}

void ChartsWidget::execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted) {
  signal_selector_ = std::move(dlg);
  signal_selector_owner_ = owner;
  signal_selector_accepted_ = std::move(accepted);
  signal_selector_->open();
}

void ChartsWidget::removeChart(ChartView *chart) {
  if (active_chart_ == chart) active_chart_ = nullptr;
  if (signal_selector_owner_ == chart) {
    signal_selector_owner_ = nullptr;
    signal_selector_accepted_ = nullptr;
  }
  auto it = std::find_if(charts_.begin(), charts_.end(), [chart](auto &c) { return c.get() == chart; });
  if (it != charts_.end()) {
    deleted_charts_.push_back(std::move(*it));  // may be called from the chart's draw; freed next frame
    charts_.erase(it);
  }
  seriesChanged();
}

void ChartsWidget::removeAll() {
  while (!charts_.empty()) removeChart(charts_.back().get());
  equations_.clear();
  equationsChanged();
  function_editor_open_ = false;
  zoomReset();
}

void ChartsWidget::drawAnalysisMenu() {
  if (dropdown::Item("New Function...")) openFunctionEditor();
  for (const auto &equation : equations_) {
    if (dropdown::Item(equation.name.c_str())) openFunctionEditor(&equation);
  }
}

void ChartsWidget::draw() {
  syncSources();
  pollEquations();
  updateState();
  deleted_charts_.clear();
  bool plot_hovered = false;
  std::vector<ChartView *> charts;  // a chart can be removed or created while it is drawn
  for (auto &c : charts_) charts.push_back(c.get());
  for (auto *c : charts) {
    c->resolveSignals();
    c->pollFields();
    bool open = true;
    const bool visible = beginDockablePanel(c->windowName(), &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    // double-clicking the tab or title bar opens the chart menu, to rename it
    auto *window = ImGui::GetCurrentWindow();
    const bool title_hovered = window->DockIsActive ?
      (window->DC.DockTabItemStatusFlags & ImGuiItemStatusFlags_HoveredRect) != 0 :
      (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(window->TitleBarRect().Min, window->TitleBarRect().Max));
    if (visible && title_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) c->focus_title_ = true;
    if (visible) {
      if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows)) active_chart_ = c;
      c->draw(ImGui::GetContentRegionAvail().x);
      plot_hovered |= c->plotHovered();
    }
    ImGui::End();
    if (!open) removeChart(c);
  }
  if (!plot_hovered) showValueTip(-1);
  drawFunctionEditor();
  if (signal_selector_ && !signal_selector_->draw()) {
    auto dlg = std::move(signal_selector_);
    auto accepted = std::move(signal_selector_accepted_);
    signal_selector_owner_ = nullptr;
    if (dlg->accepted() && accepted) accepted(*dlg);
  }
}

void ChartsWidget::removeSource(const std::string &id) {
  source_connections_.erase(id);
  source_offsets_.erase(id);
  calculated_.erase(id);
  dirty_sources_.erase(id);
  browsers_.erase(id);
  for (auto &c : charts_) c->detachSource(id);
}
