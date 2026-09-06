#define IMGUI_DEFINE_MATH_OPERATORS  // ImVec2 arithmetic, must precede imgui.h
#include "tools/cabana/ui/chart/chartswidget.h"

#include "tools/cabana/ui/threadpool.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <future>

#include "tools/cabana/settings.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"

const int MAX_COLUMN_COUNT = 4;
const int CHART_SPACING = 4;
const int START_DRAG_DISTANCE = 10;
const float LAYOUT_HORIZONTAL_SPACING = 6.0f;
const float MIN_RANGE_SLIDER_WIDTH = 40.0f;

bool LogSlider::draw(const char *label, float width) {
  return fusionSliderInt(label, &pos_, min_, max_, width);
}

ChartsWidget::ChartsWidget() {
  range_slider_.setRange(1, settings.max_cached_minutes * 60);

  tabbar_.setTabsClosable(true);
  tabbar_.setDockable(true, "ChartsPane_");
  tabbar_.setWindowFlags(ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

  column_count_ = std::clamp(settings.chart_column_count, 1, MAX_COLUMN_COUNT);
  max_chart_range_ = std::clamp(settings.chart_range, 1, settings.max_cached_minutes * 60);
  display_range_ = std::make_pair(can->minSeconds(), can->minSeconds() + max_chart_range_);
  range_slider_.setValue(max_chart_range_);

  connections_.push_back(dbc()->fileChanged.connect([this]() { removeAll(); }));
  connections_.push_back(can->eventsMerged.connect([this](const MessageEventsMap &events) { eventsMerged(events); }));
  connections_.push_back(can->msgsReceived.connect([this](const std::set<MessageId> *, bool) { updateState(); }));
  connections_.push_back(can->seeking.connect([this](double) { updateState(); }));
  connections_.push_back(can->timeRangeChanged.connect([this](const auto &) { updateState(); }));
  connections_.push_back(settings.changed.connect([this]() { settingChanged(); }));
  connections_.push_back(seriesChanged.connect([this]() { updateTabBar(); }));
  connections_.push_back(tabbar_.tabCloseRequested.connect([this](int index) { removeTab(index); }));

  newTab();
}

ChartsWidget::~ChartsWidget() = default;

std::string ChartsWidget::whatsThis() const {
  return R"(
    <b>Chart View</b><br />
    <b>Click</b>: Click to seek to a corresponding time.<br />
    <b>Drag</b>: Zoom into the chart.<br />
    <b>Shift + Drag</b>: Scrub through the chart to view values.<br />
    <b>Right Mouse</b>: Open the context menu.<br />
  )";
}

void ChartsWidget::newTab() {
  const int id = next_tab_id_++;
  int idx = tabbar_.addTab("");
  tabbar_.setTabData(idx, id);
  tabbar_.setCurrentIndex(idx);
  containers_[id] = std::make_unique<ChartsContainer>(this, id);
  updateTabBar();
}

void ChartsWidget::removeTab(int index) {
  int id = tabbar_.tabData(index);
  for (auto &c : std::vector<ChartView *>(tab_charts_[id])) {
    removeChart(c);
  }
  if (drop_container_ && drop_container_->tabId() == id) drop_container_ = nullptr;
  tab_charts_.erase(id);
  containers_.erase(id);
  tabbar_.removeTab(index);
  updateTabBar();
}

void ChartsWidget::updateTabBar() {
  for (int i = 0; i < tabbar_.count(); ++i) {
    const auto &charts_in_tab = tab_charts_[tabbar_.tabData(i)];
    tabbar_.setTabText(i, "Charts " + std::to_string(i + 1) + " (" + std::to_string((int)charts_in_tab.size()) + ")");
  }
}

ChartsContainer *ChartsWidget::container(int tab_id) {
  auto it = containers_.find(tab_id);
  return it != containers_.end() ? it->second.get() : nullptr;
}

ChartsContainer *ChartsWidget::containerAt(const ImVec2 &global_pos) {
  for (auto &[_, c] : containers_) {
    if (c->scroll && c->viewport.Contains(global_pos)) return c.get();
  }
  return nullptr;
}

ChartsContainer *ChartsWidget::containerOf(ChartView *chart) {
  for (auto &[id, list] : tab_charts_) {
    if (std::find(list.begin(), list.end(), chart) != list.end()) return container(id);
  }
  return nullptr;
}

void ChartsWidget::eventsMerged(const MessageEventsMap &new_events) {
  std::vector<std::future<void>> futures;
  for (auto &c : charts_) {
    futures.push_back(ThreadPool::instance().run([c = c.get(), &new_events]() { c->updateSeries(nullptr, &new_events); }));
  }
  for (auto &f : futures) f.get();
}

void ChartsWidget::zoomReset() {
  can->setTimeRange(std::nullopt);
  zoom_undo_stack_.clear();
}

ImRect ChartsWidget::chartVisibleRect(ChartView *chart) {
  ImRect r = chart->rect();
  if (auto c = containerOf(chart)) r.ClipWith(c->viewport);
  return r;
}

void ChartsWidget::showValueTip(double sec) {
  if (chartDragActive()) sec = -1;  // no value tip while a drag is in progress
  showTip(sec);
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

  const auto &range = time_range ? *time_range : display_range_;
  for (auto &c : charts_) {
    c->updatePlot(cur_sec, range.first, range.second);
  }
}

void ChartsWidget::setMaxChartRange(int value) {
  max_chart_range_ = settings.chart_range = value;
  updateState();
}

void ChartsWidget::drawToolBar() {
  beginToolbar();
  float slider_width = 150.0f;
  const bool is_zoomed = can->timeRange().has_value();

  // the labels are captured by reference, they outlive the draw calls below
  std::vector<ToolbarItem> items;
  items.push_back({toolbarButtonWidth(icon::PLUS_SQUARE), [this]() {
    if (toolButton("new_plot_btn", icon::PLUS_SQUARE, "New Chart")) newChart();
  }});
  items.push_back({toolbarButtonWidth(icon::WINDOW_STACK), [this]() {
    if (toolButton("new_tab_btn", icon::WINDOW_STACK, "New Tab")) newTab();
  }});
  const std::string title_label = "Charts: " + std::to_string(charts_.size());
  items.push_back({ImGui::CalcTextSize(title_label.c_str()).x + LAYOUT_HORIZONTAL_SPACING, [&title_label]() {
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(title_label.c_str());
    ImGui::SameLine(0.0f, LAYOUT_HORIZONTAL_SPACING);
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
  }});

  const int type_count = (int)std::size(SERIES_TYPE_NAMES);
  const std::string chart_type_text = std::string("Type:  ") + SERIES_TYPE_NAMES[std::clamp(settings.chart_series_type, 0, type_count - 1)];
  items.push_back({menuButtonWidth(chart_type_text), [this, &chart_type_text]() {
    menuButton("chart_type", chart_type_text, "chart_type_menu");
    if (ImGui::BeginPopup("chart_type_menu")) {
      for (int i = 0; i < type_count; ++i) {
        if (ImGui::MenuItem(SERIES_TYPE_NAMES[i])) {
          settings.chart_series_type = i;
          settingChanged();
        }
      }
      ImGui::EndPopup();
    }
  }});

  const std::string columns_action_text = "Columns:  " + std::to_string(column_count_);
  const ChartsContainer *drawing = container(currentTabId());
  if (drawing && drawing->columnsSelectable()) {
    items.push_back({menuButtonWidth(columns_action_text), [this, &columns_action_text]() {
      menuButton("columns", columns_action_text, "columns_menu");
      if (ImGui::BeginPopup("columns_menu")) {
        for (int i = 0; i < MAX_COLUMN_COUNT; ++i) {
          if (ImGui::MenuItem(std::to_string(i + 1).c_str())) setColumnCount(i + 1);
        }
        ImGui::EndPopup();
      }
    }});
  }

  // the spacer right aligns the rest
  const size_t spacer_index = items.size();
  size_t slider_index = (size_t)-1;
  const std::string range_lb = is_zoomed ? std::string() : utils::formatSeconds(max_chart_range_);
  std::string reset_zoom_text;
  if (!is_zoomed) {
    items.push_back({ImGui::CalcTextSize(range_lb.c_str()).x, [&range_lb]() {
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(range_lb.c_str());
    }});
    slider_index = items.size();
    items.push_back({slider_width, [this, &slider_width]() {
      if (range_slider_.draw("##range_slider", slider_width)) setMaxChartRange(range_slider_.value());
      ImGui::SetItemTooltip("Set the chart range");
    }});
  } else {
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f-%.2f", can->timeRange()->first, can->timeRange()->second);
    reset_zoom_text = buf;
    items.push_back({toolbarButtonWidth(icon::ARROW_COUNTERCLOCKWISE), [this]() {
      ImGui::BeginDisabled(!zoom_undo_stack_.canUndo());
      if (toolButton("undo_zoom", icon::ARROW_COUNTERCLOCKWISE, "Undo Zoom")) zoom_undo_stack_.undo();
      ImGui::EndDisabled();
    }});
    items.push_back({toolbarButtonWidth(icon::ARROW_CLOCKWISE), [this]() {
      ImGui::BeginDisabled(!zoom_undo_stack_.canRedo());
      if (toolButton("redo_zoom", icon::ARROW_CLOCKWISE, "Redo Zoom")) zoom_undo_stack_.redo();
      ImGui::EndDisabled();
    }});
    items.push_back({toolbarButtonWidth(std::string(icon::ZOOM_OUT) + " " + reset_zoom_text), [this, &reset_zoom_text]() {
      if (toolButton("reset_zoom_btn", icon::ZOOM_OUT, "Reset Zoom", reset_zoom_text.c_str())) zoomReset();
    }});
  }
  items.push_back({toolbarButtonWidth(icon::X_SQUARE), [this]() {
    ImGui::BeginDisabled(charts_.empty());
    if (toolButton("remove_all_btn", icon::X_SQUARE, "Remove all charts")) removeAll();
    ImGui::EndDisabled();
  }});

  // the slider shrinks first, the buttons stay pinned to the right edge
  if (slider_index != (size_t)-1) {
    const float shrink = std::min(slider_width - MIN_RANGE_SLIDER_WIDTH, toolbarWidth(items, spacer_index) - ImGui::GetContentRegionAvail().x);
    if (shrink > 0.0f) {
      slider_width -= shrink;
      items[slider_index].width = slider_width;
    }
  }
  drawToolbar(items, spacer_index);
  endToolbar();
}

void ChartsWidget::settingChanged() {
  if (range_slider_.maximum() != settings.max_cached_minutes * 60) {
    range_slider_.setRange(1, settings.max_cached_minutes * 60);
  }
  for (auto &c : charts_) {
    c->setSeriesType((SeriesType)settings.chart_series_type);
  }
}

ChartView *ChartsWidget::findChart(const MessageId &id, const cabana::Signal *sig) {
  for (auto &c : charts_)
    if (c->hasSignal(id, sig)) return c.get();
  return nullptr;
}

ChartView *ChartsWidget::createChart(int pos) {
  auto chart = std::make_unique<ChartView>(can->timeRange().value_or(display_range_), this);
  ChartView *ptr = chart.get();
  pos = std::clamp(pos, 0, (int)charts_.size());
  charts_.insert(charts_.begin() + pos, std::move(chart));
  auto &cur = currentCharts();
  cur.insert(cur.begin() + std::min<int>(pos, cur.size()), ptr);
  return ptr;
}

void ChartsWidget::showChart(const MessageId &id, const cabana::Signal *sig, bool show, bool merge) {
  ChartView *chart = findChart(id, sig);
  if (show && !chart) {
    chart = merge && currentCharts().size() > 0 ? currentCharts().front() : createChart();
    chart->addSignal(id, sig);
    updateState();
  } else if (!show && chart) {
    chart->removeIf([&](auto &s) { return s.msg_id == id && s.sig == sig; });
  }
}

void ChartsWidget::splitChart(ChartView *src_chart) {
  if (src_chart->signals().size() > 1) {
    auto it = std::find_if(charts_.begin(), charts_.end(), [src_chart](auto &c) { return c.get() == src_chart; });
    const int pos = it - charts_.begin() + 1;
    for (auto &s : src_chart->takeExtraSignals()) {
      createChart(pos)->adoptSignal(std::move(s));
    }
    updateState();
  }
}

std::vector<std::string> ChartsWidget::serializeChartIds() const {
  std::vector<std::string> chart_ids;
  for (auto &c : charts_) {
    std::string ids;
    for (const auto &s : c->signals()) {
      if (!ids.empty()) ids += ',';
      ids += s.msg_id.toString() + "|" + s.sig->name;
    }
    chart_ids.push_back(ids);
  }
  std::reverse(chart_ids.begin(), chart_ids.end());
  return chart_ids;
}

void ChartsWidget::restoreChartsFromIds(const std::vector<std::string> &chart_ids) {
  for (const auto &chart_id : chart_ids) {
    int index = 0;
    for (const auto &part : utils::split(chart_id, ',')) {
      const size_t sep = part.find('|');
      if (sep == std::string::npos) continue;
      MessageId msg_id = MessageId::fromString(part.substr(0, sep));
      if (auto *msg = dbc()->msg(msg_id))
        if (auto *sig = msg->sig(part.substr(sep + 1)))
          showChart(msg_id, sig, true, index++ > 0);
    }
  }
}

void ChartsWidget::setColumnCount(int n) {
  n = std::clamp(n, 1, MAX_COLUMN_COUNT);
  column_count_ = settings.chart_column_count = n;
}

void ChartsContainer::updateLayout() {
  const float container_width = geometry_.GetWidth();
  if (container_width <= 0) return;

  int n = MAX_COLUMN_COUNT;
  for (; n > 1; --n) {
    if ((n * CHART_MIN_WIDTH + (n - 1) * CHART_SPACING) < container_width) break;
  }

  columns_selectable_ = n > 1;
  column_count_ = std::min(charts_widget_->column_count_, n);
}

void ChartsWidget::startChartDrag(ChartView *chart, const ImVec2 &global_pos) {
  stopAutoScroll();
  drag_ = {.source = chart, .press_pos = global_pos};
  showValueTip(-1);  // no value tip while a drag is in progress
  // the drag preview re-renders the tile at CHART_MIN_WIDTH
  drag_preview_size_ = ImVec2(CHART_MIN_WIDTH, (float)settings.chart_height);
}

void ChartsWidget::dragChartMove(const ImVec2 &global_pos) {
  if (!drag_.active) {
    ImVec2 d = global_pos - drag_.press_pos;
    if (std::abs(d.x) + std::abs(d.y) < START_DRAG_DISTANCE) return;
    drag_.active = true;
    drag_preview_visible_ = true;
  }
  drag_preview_pos_ = global_pos + ImVec2(5, 5);

  // hovering a tab switches to it so the chart can be dropped into another tab
  int tab = tabbar_.tabAt(global_pos);
  if (tab >= 0 && tab != tabbar_.currentIndex()) {
    tabbar_.setCurrentIndex(tab);
  }

  // the drop goes to the tab whose chart area is under the pointer
  ChartsContainer *drop = containerAt(global_pos);
  if (std::exchange(drop_container_, drop) != drop && drop_container_ == nullptr) {
    for (auto &[_, c] : containers_) c->setDropIndicator({});
  }
  ChartView *target = nullptr;
  if (drop) {
    for (auto c : tab_charts_[drop->tabId()]) {
      if (c != drag_.source && c->rect().Contains(global_pos)) {
        target = c;
        break;
      }
    }
  }
  if (std::exchange(drop_target_, target) != target) {
    for (auto &c : charts_) c->setDropHighlight(c.get() == target);
  }
  for (auto &[_, c] : containers_) {
    const bool on_background = c.get() == drop && !target && !c->childAt(global_pos);
    c->setDropIndicator(on_background ? global_pos : ImVec2());
  }
  if (drop) startAutoScroll(global_pos);
}

void ChartsWidget::cancelChartDrag() {
  drag_ = {};
  stopAutoScroll();
  drag_preview_visible_ = false;
  for (auto &[_, c] : containers_) c->setDropIndicator({});
  drop_container_ = nullptr;
  if (auto target = std::exchange(drop_target_, nullptr)) target->setDropHighlight(false);
}

void ChartsWidget::dragChartRelease(const ImVec2 &global_pos) {
  ChartView *source = drag_.source;
  bool active = drag_.active;
  ChartView *target = drop_target_;
  ChartsContainer *drop = drop_container_;
  cancelChartDrag();
  if (!active) return;

  if (target) {
    // merge source into target
    target->takeSignalsFrom(source);
  } else if (drop && !drop->childAt(global_pos)) {
    // reorder within the tab, or move into another tab
    auto w = drop->getDropAfter(global_pos);
    if (w != source) {
      for (auto &[_, list] : tab_charts_) {
        list.erase(std::remove(list.begin(), list.end(), source), list.end());
      }
      auto &cur = tab_charts_[drop->tabId()];
      int to = w ? std::find(cur.begin(), cur.end(), w) - cur.begin() + 1 : 0;
      cur.insert(cur.begin() + to, source);
      updateTabBar();
    }
  }
}

void ChartsWidget::drawDragPreview() {
  if (!drag_preview_visible_ || !drag_.source) return;
  // the drag preview is the whole tile (header + axes + plot) at 50% alpha, re-rendered into a window that
  // takes no input, so the live chart keeps handling the mouse.
  ImGui::SetNextWindowPos(drag_preview_pos_);
  ImGui::SetNextWindowSize(drag_preview_size_);
  ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.5f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  const ImGuiWindowFlags flags = ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoDecoration |
                                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                                 ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoDocking;
  if (ImGui::Begin("##chart_drag_ghost", nullptr, flags)) {
    drag_.source->drawGhost(drag_preview_size_.x);
  }
  ImGui::End();
  ImGui::PopStyleVar(3);
}

void ChartsWidget::startAutoScroll(const ImVec2 &global_pos) {
  auto_scroll_pos_ = global_pos;
  if (!auto_scroll_timer_active_) auto_scroll_timer_next_ = ImGui::GetTime() + 0.05;
  auto_scroll_timer_active_ = true;
}

void ChartsWidget::stopAutoScroll() {
  auto_scroll_timer_active_ = false;
  auto_scroll_count_ = 0;
}

void ChartsWidget::doAutoScroll() {
  ChartsContainer *drop = drop_container_;
  if (!drop || !drop->scroll) return;
  ImGuiWindow *charts_scroll_ = drop->scroll;
  const int page_step = drop->viewport.GetHeight();
  if (auto_scroll_count_ < page_step) {
    ++auto_scroll_count_;
  }

  int value = charts_scroll_->Scroll.y;
  ImVec2 pos = auto_scroll_pos_;
  ImRect area = drop->viewport;

  int new_value = value;
  if (pos.y - area.Min.y < settings.chart_height / 2) {
    new_value = value - auto_scroll_count_;
  } else if (area.Max.y - pos.y < settings.chart_height / 2) {
    new_value = value + auto_scroll_count_;
  }
  new_value = std::clamp<int>(new_value, 0, charts_scroll_->ScrollMax.y);
  if (new_value != value) ImGui::SetScrollY(charts_scroll_, new_value);
  if (value == new_value) {
    stopAutoScroll();
  } else if (chartDragActive()) {
    // refresh the drop indicator/target at the new scroll position
    dragChartMove(auto_scroll_pos_);
  }
}

void ChartsWidget::newChart() {
  execSignalSelector(std::make_unique<SignalSelector>("New Chart"), nullptr, [this](SignalSelector &dlg) {
    const auto &items = dlg.selectedItems();
    if (!items.empty()) {
      auto c = createChart();
      for (const auto &it : items) {
        c->addSignal(it.msg_id, it.sig);
      }
      updateState();
    }
  });
}

void ChartsWidget::execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted) {
  signal_selector_ = std::move(dlg);
  signal_selector_owner_ = owner;
  signal_selector_accepted_ = std::move(accepted);
  signal_selector_->open();
}

void ChartsWidget::removeChart(ChartView *chart) {
  if (drag_.source == chart) cancelChartDrag();
  if (drop_target_ == chart) drop_target_ = nullptr;
  if (signal_selector_owner_ == chart) {
    signal_selector_owner_ = nullptr;
    signal_selector_accepted_ = nullptr;
  }
  auto it = std::find_if(charts_.begin(), charts_.end(), [chart](auto &c) { return c.get() == chart; });
  if (it != charts_.end()) {
    deleted_charts_.push_back(std::move(*it));  // may be called from the chart's draw; freed next frame
    charts_.erase(it);
  }
  for (auto &[_, list] : tab_charts_) {
    list.erase(std::remove(list.begin(), list.end(), chart), list.end());
  }
  seriesChanged();
}

void ChartsWidget::removeAll() {
  while (tabbar_.count() > 1) removeTab(1);
  std::vector<ChartView *> all;
  for (auto &c : charts_) all.push_back(c.get());
  for (auto c : all) removeChart(c);
  for (auto &[_, list] : tab_charts_) list.clear();
  zoomReset();
}

void ChartsWidget::handleEvents() {
  if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_AnyWindow)) {
    if (chartDragActive()) cancelChartDrag();
    showValueTip(-1);
  }

  // route all mouse events to the chart drag, even when the source chart is hidden by a tab switch
  if (chartDragActive()) {
    if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
      dragChartMove(ImGui::GetMousePos());
    } else {
      dragChartRelease(ImGui::GetMousePos());
    }
  }

  if (!value_tip_visible_) return;

  // the tip is drawn on the foreground draw list, so the mouse is never "on the tip"
  const ImVec2 delta = ImGui::GetIO().MouseDelta;
  if (!any_plot_hovered_ && (delta.x != 0 || delta.y != 0 || !pane_hovered_)) {
    showValueTip(-1);  // the mouse moved off the plot or out of the charts windows
  }
}

void ChartsWidget::draw() {
  deleted_charts_.clear();
  ImGui::PushID(this);
  if (auto_scroll_timer_active_ && ImGui::GetTime() >= auto_scroll_timer_next_) {
    auto_scroll_timer_next_ = ImGui::GetTime() + 0.05;
    doAutoScroll();
  }
  // the drop target and indicator must be resolved before the charts are painted, otherwise the highlight
  // lags a frame behind the target used on release and the drop lands on the wrong chart
  handleEvents();

  any_plot_hovered_ = false;
  pane_hovered_ = false;
  tabbar_.draw([this](int index, bool visible) {
    if (visible) drawTab(index);
  });

  drawDragPreview();

  if (signal_selector_ && !signal_selector_->draw()) {
    auto dlg = std::move(signal_selector_);
    auto accepted = std::move(signal_selector_accepted_);
    signal_selector_owner_ = nullptr;
    if (dlg->accepted() && accepted) accepted(*dlg);
  }
  ImGui::PopID();
}

void ChartsWidget::drawTab(int index) {
  drawing_tab_ = index;
  ChartsContainer *c = container(tabbar_.tabData(index));
  ImGui::PushID(c);
  if (paneDrawn) paneDrawn(ImGui::GetCurrentWindow()->Rect());
  if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows)) {
    pane_hovered_ = true;
    // the mouse back button undoes a zoom; there is no swipe-back gesture
    if (ImGui::IsMouseClicked(3)) zoom_undo_stack_.undo();
  }
  drawToolBar();
  if (ImGui::BeginChild("charts_scroll", ImVec2(0, 0), ImGuiChildFlags_None, 0)) {
    c->scroll = ImGui::GetCurrentWindow();
    c->viewport = c->scroll->InnerRect;
    c->draw();
  }
  ImGui::EndChild();
  ImGui::PopID();
  drawing_tab_ = -1;
}

const std::vector<ChartView *> &ChartsContainer::charts() const {
  return charts_widget_->tab_charts_[tab_id_];
}

void ChartsContainer::draw() {
  ImGuiWindow *window = ImGui::GetCurrentWindow();
  const ImVec2 start = ImGui::GetCursorScreenPos();
  geometry_ = ImRect(start, start + ImVec2(window->InnerRect.GetWidth(), 0));
  updateLayout();

  const int n = std::max(column_count_, 1);
  const float spacing = CHART_SPACING;
  const float width = (geometry_.GetWidth() - (n - 1) * spacing) / n;
  const ImVec2 origin = ImGui::GetCursorScreenPos() + ImVec2(0, CHART_SPACING);
  auto current_charts = charts();  // copy: drawing may remove charts
  float bottom = origin.y;
  const bool aligned = ImPlot::BeginAlignedPlots("charts_align", true);
  for (int i = 0; i < current_charts.size(); ++i) {
    ImVec2 pos = origin + ImVec2((i % n) * (width + spacing), (i / n) * (settings.chart_height + spacing));
    ImGui::SetCursorScreenPos(pos);
    current_charts[i]->draw(width);
    bottom = std::max(bottom, pos.y + settings.chart_height);
    if (current_charts[i]->plotHovered()) charts_widget_->any_plot_hovered_ = true;  // the window must be hovered too
  }
  if (aligned) ImPlot::EndAlignedPlots();
  ImGui::SetCursorScreenPos(ImVec2(origin.x, bottom));
  ImGui::Dummy(ImVec2(geometry_.GetWidth(), CHART_SPACING));
  geometry_.Max.y = bottom + CHART_SPACING;
  drawDropIndicator();
}

void ChartsContainer::drawDropIndicator() {
  if (!(drop_indicator_pos_.x == 0 && drop_indicator_pos_.y == 0) && !childAt(drop_indicator_pos_)) {
    ImRect r = geometry_;
    r.Max.y = r.Min.y + CHART_SPACING;
    if (auto insert_after = getDropAfter(drop_indicator_pos_)) {
      float h = r.GetHeight();
      r.Min.y = insert_after->rect().Max.y;
      r.Max.y = r.Min.y + h;
    }

    ImGui::GetWindowDrawList()->AddRectFilled(r.Min, r.Max, ImGui::GetColorU32(ImGuiCol_Header));
  }
}

ChartView *ChartsContainer::getDropAfter(const ImVec2 &pos) const {
  const auto &charts = this->charts();
  auto it = std::find_if(charts.crbegin(), charts.crend(), [&pos](auto c) {
    const ImRect &area = c->rect();
    return pos.x >= area.Min.x && pos.x <= area.Max.x && pos.y >= area.Max.y;
  });
  return it == charts.crend() ? nullptr : *it;
}

ChartView *ChartsContainer::childAt(const ImVec2 &pos) const {
  for (auto c : charts()) {
    if (c->rect().Contains(pos)) return c;
  }
  return nullptr;
}
