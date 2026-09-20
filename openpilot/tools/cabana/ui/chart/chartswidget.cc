#define IMGUI_DEFINE_MATH_OPERATORS  // ImVec2 arithmetic, must precede imgui.h
#include "tools/cabana/ui/chart/chartswidget.h"

#include "tools/cabana/ui/threadpool.h"

#include <algorithm>
#include <cmath>
#include <cfloat>
#include "tools/cabana/core/source.h"
#include <cstdio>
#include <future>

#include "tools/cabana/settings.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"


bool LogSlider::draw(const char *label, float width) {
  return fusionSliderInt(label, &pos_, min_, max_, width);
}

ChartManager::ChartManager() {
  range_slider_.setRange(1, settings.max_cached_minutes * 60);
  max_chart_range_ = std::clamp(settings.chart_range, 1, settings.max_cached_minutes * 60);
  display_range_ = {0, max_chart_range_};
  range_slider_.setValue(max_chart_range_);
  connections_.push_back(settings.changed.connect([this]() { settingChanged(); }));
}

void ChartManager::syncSources() {
  for (auto *source : sources()) {
    const auto id = source->source_id;
    if (!source_connections_.count(id)) {
      auto &connections = source_connections_[id];
      connections.push_back(source->fieldsChanged.connect([this]() { fieldsChanged(); for (auto &c : charts_) c->updateFields(); }));
      connections.push_back(source->eventsMerged.connect([this](const MessageEventsMap &events) { eventsMerged(events); }));
      connections.push_back(source->database()->fileChanged.connect([this, id]() {
        for (auto &c : charts_) { c->detachSource(id); c->resolveSignals(); }
      }));
      connections.push_back(source->database()->signalRemoved.connect([this](const cabana::Signal *sig) {
        for (auto &c : charts_) c->signalRemoved(sig);
      }));
      connections.push_back(source->database()->signalUpdated.connect([this](const cabana::Signal *sig) {
        for (auto &c : charts_) c->signalUpdated(sig);
      }));
      connections.push_back(source->database()->msgRemoved.connect([this, id](MessageId msg) {
        for (auto &c : charts_) c->removeIf([&](const auto &s) {
          auto *owner = sourceById(id);
          return s.source_id == id && s.path.empty() && s.msg_id.address == msg.address && owner && !owner->database()->msg(s.msg_id);
        });
      }));
      source_offsets_[id] = source->timeline_offset;
      dirty_sources_.insert(id);
      for (auto &c : charts_) c->updateFields();
    }
    if (source_offsets_[id] != source->timeline_offset) {
      source_offsets_[id] = source->timeline_offset;
      dirty_sources_.insert(id);
      for (auto &c : charts_) c->updateFields();
      for (auto &c : charts_) { c->updateSeries(); c->updateFields(); }
    }
  }
  for (auto it = source_connections_.begin(); it != source_connections_.end();) {
    if (!sourceById(it->first)) it = source_connections_.erase(it);
    else ++it;
  }
}

std::vector<ChartView *> ChartManager::currentCharts() const {
  std::vector<ChartView *> result;
  for (auto &c : charts_) result.push_back(c.get());
  return result;
}

std::vector<std::string> ChartManager::windowNames() const {
  std::vector<std::string> result;
  for (auto &c : charts_) result.push_back(c->windowName());
  return result;
}

ChartManager::~ChartManager() = default;

std::string ChartManager::whatsThis() const {
  const std::string mod = MOD_KEY;
  return "<b>Chart View</b><br />"
         "<b>Click</b>: Click to seek to a corresponding time.<br />"
         "<b>Drag</b>: Zoom into the chart.<br />"
         "<b>" + mod + " + Drag</b>: Pan the time range.<br />"
         "<b>" + mod + " + Wheel</b>: Zoom around the pointer.<br />"
         "<b>Signal right-click</b>: Transforms and statistics.<br />"
         "<b>Shift + Drag</b>: Scrub through the chart to view values.<br />"
         "<b>Right-click</b>: Open the context menu.<br />";
}

void ChartManager::eventsMerged(const MessageEventsMap &new_events) {
  for (auto &c : charts_) c->updateSeries(nullptr, &new_events, can->source_id);
}

void ChartManager::zoomReset() {
  can->setTimeRange(std::nullopt);
  zoom_undo_stack_.clear();
}

ImRect ChartManager::chartVisibleRect(ChartView *chart) {
  ImRect r = chart->rect();

  return r;
}

void ChartManager::showValueTip(double sec) {
  if (sec < 0 && !value_tip_visible_) return;

  value_tip_visible_ = sec >= 0;
  for (auto c : currentCharts()) {
    value_tip_visible_ ? c->showTip(sec) : c->hideTip();
  }
}

void ChartManager::updateState() {
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

  const auto &range = time_range ? *time_range : display_range_;
  for (auto &c : charts_) {
    c->updatePlot(cur_sec + can->timeline_offset, range.first + can->timeline_offset, range.second + can->timeline_offset);
  }
}

void ChartManager::setMaxChartRange(int value) {
  max_chart_range_ = settings.chart_range = value;
  updateState();
}

void ChartManager::settingChanged() {
  if (range_slider_.maximum() != settings.max_cached_minutes * 60) {
    range_slider_.setRange(1, settings.max_cached_minutes * 60);
  }
}

ChartView *ChartManager::findChart(const MessageId &id, const cabana::Signal *sig) {
  for (auto &c : charts_)
    if (c->hasSignal(id, sig)) return c.get();
  return nullptr;
}

ChartView *ChartManager::createChart(int pos, bool restoring) {
  auto chart = std::make_unique<ChartView>(can->timeRange().value_or(display_range_), this);
  ChartView *ptr = chart.get();
  pos = std::clamp(pos, 0, (int)charts_.size());
  charts_.insert(charts_.begin() + pos, std::move(chart));
  ptr->widget_id = std::to_string(next_chart_id_++);
  if (!restoring) dockNewPanel(ptr->windowName());
  active_chart_ = ptr;
  chartAdded();
  return ptr;
}

void ChartManager::showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge) {
  ChartView *chart = findChart(id, sig);
  if (show && !chart) {
    chart = merge && active_chart_ ? active_chart_ : createChart();
    chart->addSignal(id, sig);
    updateState();
  } else if (!show && chart) {
    chart->removeIf([&](auto &s) { return s.msg_id == id && s.sig == sig; });
  }
}

void ChartManager::splitChart(ChartView *src_chart) {
  if (src_chart->signals().size() > 1) {
    auto current = currentCharts();
    const int pos = std::find(current.begin(), current.end(), src_chart) - current.begin() + 1;
    for (auto &s : src_chart->takeExtraSignals()) {
      createChart(pos)->adoptSignal(std::move(s));
    }
    updateState();
  }
}

void ChartManager::newChart() {
  createChart();
  updateState();
}

void ChartManager::execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted) {
  signal_selector_ = std::move(dlg);
  signal_selector_owner_ = owner;
  signal_selector_accepted_ = std::move(accepted);
  signal_selector_->open();
}

void ChartManager::removeChart(ChartView *chart) {
  if (active_chart_ == chart) active_chart_ = nullptr;
  if (rename_chart_ == chart) rename_chart_ = nullptr;
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

void ChartManager::removeAll() {
  std::vector<ChartView *> all;
  for (auto &c : charts_) all.push_back(c.get());
  for (auto c : all) removeChart(c);
  ++equation_revision_;
  browsers_.clear();
  function_editor_open_ = false;
  equations_.clear();
  source_calculated_.clear();
  dirty_sources_.clear();
  equation_errors_.clear();
  rebuildSignalBrowser();
  zoomReset();
}

void ChartManager::drawAnalysisMenu() {
  if (dropdown::Item("New Function...")) openFunctionEditor();
  for (const auto &equation : equations_) {
    if (dropdown::Item(equation.name.c_str())) openFunctionEditor(&equation);
  }
}

void ChartManager::draw() {
  syncSources();
  pollFields();
  updateState();
  deleted_charts_.clear();
  any_plot_hovered_ = false;
  bool begin_rename = false;
  for (auto *c : currentCharts()) {
    c->resolveSignals();
    c->pollFields();
    bool open = true;
    const bool visible = beginDockablePanel(c->windowName(), &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    auto *window = ImGui::GetCurrentWindow();
    const bool title_hovered = window->DockIsActive ?
      (window->DC.DockTabItemStatusFlags & ImGuiItemStatusFlags_HoveredRect) != 0 :
      (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(window->TitleBarRect().Min, window->TitleBarRect().Max));
    if (open && title_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
        !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
      rename_chart_ = c;
      rename_title_ = c->title;
      begin_rename = true;
    }
    if (visible) {
      if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows)) active_chart_ = c;
      c->draw(ImGui::GetContentRegionAvail().x);
      any_plot_hovered_ |= c->plotHovered();
    }
    ImGui::End();
    if (!open) removeChart(c);
  }
  if (!any_plot_hovered_) showValueTip(-1);
  if (begin_rename && rename_chart_) ImGui::OpenPopup("Rename chart");
  setNextDialogWindow(ImVec2(420, 0));
  if (ImGui::BeginPopupModal("Rename chart", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
    if (!rename_chart_) {
      ImGui::CloseCurrentPopup();
    } else {
      ImGui::TextUnformatted("Chart title");
      if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
      ImGui::SetNextItemWidth(-1);
      bool save = inputText("##rename_chart_title", &rename_title_, "Automatic title",
                            ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_EnterReturnsTrue);
      ImGui::TextDisabled("Leave blank to use the signal name.");
      bool cancel = false;
      dialogButtons("Rename", &save, &cancel);
      if (save || cancel) {
        if (save) rename_chart_->title = utils::trimmed(rename_title_);
        rename_chart_ = nullptr;
        ImGui::CloseCurrentPopup();
      }
    }
    ImGui::EndPopup();
  }
  drawFunctionEditor();
  if (signal_selector_ && !signal_selector_->draw()) {
    auto dlg = std::move(signal_selector_);
    auto accepted = std::move(signal_selector_accepted_);
    signal_selector_owner_ = nullptr;
    if (dlg->accepted() && accepted) accepted(*dlg);
  }
}

void ChartManager::removeSource(const std::string &id) {
  source_connections_.erase(id);
  source_offsets_.erase(id);
  source_calculated_.erase(id);
  dirty_sources_.erase(id);
  browsers_.erase(id);
  signal_selector_.reset();
  signal_selector_owner_ = nullptr;
  signal_selector_accepted_ = {};
  for (auto &c : charts_) c->detachSource(id);
}
