#define IMGUI_DEFINE_MATH_OPERATORS  // ImVec2 arithmetic, must precede imgui.h
#include "tools/cabana/ui/chart/chartswidget.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>
#include <random>
#include <fstream>
#include <filesystem>
#include "tools/cabana/analysis/workspace.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/ui/dialogs/messagebox.h"

#include "tools/cabana/settings.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/panel.h"
#include "tools/cabana/utils/strings.h"

const float MIN_RANGE_SLIDER_WIDTH = 40.0f;

bool LogSlider::draw(const char *label, float width) {
  return fusionSliderInt(label, &pos_, min_, max_, width);
}

ChartsWidget::ChartsWidget(cabana::AnalysisSession &session) : session(session) {
  range_slider_.setRange(1, settings.max_cached_minutes * 60);

  tabbar_.setAutoHide(true);
  tabbar_.setUsesScrollButtons(true);
  tabbar_.setTabsClosable(true);

  max_chart_range_ = std::clamp(settings.chart_range, 1, settings.max_cached_minutes * 60);
  display_range_ = std::make_pair(can->minSeconds(), can->minSeconds() + max_chart_range_);
  range_slider_.setValue(max_chart_range_);

  connections_.push_back(can->eventsMerged.connect([this](const MessageEventsMap &events) { eventsMerged(events); }));
  connections_.push_back(can->msgsReceived.connect([this](const std::set<MessageId> *, bool) { updateState(); }));
  connections_.push_back(can->seeking.connect([this](double) { updateState(); }));
  connections_.push_back(can->timeRangeChanged.connect([this](const auto &) { updateState(); }));
  connections_.push_back(settings.changed.connect([this]() { settingChanged(); }));
  connections_.push_back(tabbar_.tabCloseRequested.connect([this](int index) { removeTab(index); }));
  connections_.push_back(tabbar_.tabContextMenu.connect([this](int index) {
    if (dropdown::BeginPopupContextItem()) {
      if (dropdown::Item("Close Other Tabs")) {
        tabbar_.moveTab(index, 0);
        tabbar_.setCurrentIndex(0);
        while (tabbar_.count() > 1) removeTab(1);
      }
      dropdown::EndPopup();
    }
  }));
  connections_.push_back(tabbar_.currentChanged.connect([this](int index) {
    if (index != -1) showValueTip(-1);
  }));

  connections_.push_back(can->fieldsChanged.connect([this]() { updateState(); }));
  newTab();
}

ChartsWidget::~ChartsWidget() = default;

std::string ChartsWidget::whatsThis() const {
  return R"(
    <b>Chart View</b><br />
    <b>Click</b>: Click to seek to a corresponding time.<br />
    <b>Drag</b>: Zoom into the chart.<br />
    <b>Shift + Drag</b>: Scrub through the chart to view values.<br />
    <b>Right-click</b>: Open the context menu.<br />
  )";
}

void ChartsWidget::newTab() {
  static int tab_unique_id = 0;
  int idx = tabbar_.addTab("Page " + std::to_string(tabbar_.count() + 1));
  const int id = tab_unique_id++;
  tabbar_.setTabData(idx, id);
  std::random_device random;
  page_ids_[id] = std::to_string(random()) + "-" + std::to_string(random());
  page_layouts_[page_ids_[id]] = json11::Json::object{{"panes", json11::Json::array{}}};
  tabbar_.setCurrentIndex(idx);
}

void ChartsWidget::removeTab(int index) {
  int id = tabbar_.tabData(index);
  for (auto &c : std::vector<ChartView *>(tab_charts_[id])) {
    removeChart(c);
  }
  tab_charts_.erase(id);
  page_layouts_.erase(page_ids_[id]);
  page_ids_.erase(id);
  tabbar_.removeTab(index);
  if (!tabbar_.count()) newTab();
}


void ChartsWidget::eventsMerged(const MessageEventsMap &new_events) {
  updateState();
}

void ChartsWidget::zoomReset() {
  can->setTimeRange(std::nullopt);
  zoom_undo_stack_.clear();
}

void ChartsWidget::showValueTip(double sec) {
  session.inspect(sec);
  showTip(sec);
  if (sec < 0 && !value_tip_visible_) return;

  value_tip_visible_ = sec >= 0;
  for (auto c : currentCharts()) {
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

void ChartsWidget::drawToolBar(std::vector<ToolbarItem> items) {
  float slider_width = 150.0f;
  const bool is_zoomed = can->timeRange().has_value();

  // the labels are captured by reference, they outlive the draw calls below
  items.push_back(toolbarTextAction("new_plot_btn", "Add Plot", [this]() { newChart(); }));
  items.push_back(toolbarTextAction("new_tab_btn", "Add Page", [this]() { newTab(); }));

  const int type_count = (int)std::size(SERIES_TYPE_NAMES);
  const std::string chart_type_text = std::string("Plot style: ") + SERIES_TYPE_NAMES[std::clamp(settings.chart_series_type, 0, type_count - 1)];
  auto chart_type_items = [this]() {
    for (int i = 0; i < type_count; ++i) {
      if (dropdown::Item(SERIES_TYPE_NAMES[i], nullptr, settings.chart_series_type == i)) {
        settings.chart_series_type = i;
        for (auto &c : charts_) c->setSeriesType((SeriesType)i);
      }
    }
  };
  items.push_back(toolbarMenu("chart_type", chart_type_text, "Plot style", chart_type_items));

  items.push_back(toolbarMenu("page", "Page Options", "Page Options", [this]() {
    if (dropdown::Item("Duplicate page")) {
      auto document = workspace().object_items();
      auto pages = document["pages"].array_items();
      auto copy = pages[tabbar_.currentIndex()].object_items();
      std::random_device random;
      const std::string suffix = "-" + std::to_string(random());
      copy["id"] = copy["id"].string_value() + suffix;
      copy["name"] = copy["name"].string_value() + " copy";
      auto panes = copy["panes"].array_items();
      std::map<std::string, std::string> ids;
      for (auto &pane : panes) {
        auto object = pane.object_items();
        const auto old = object["id"].string_value();
        object["id"] = old + suffix;
        ids["###Chart/" + old] = "###Chart/" + old + suffix;
        pane = object;
      }
      std::function<json11::Json(const json11::Json &)> remap = [&](const json11::Json &value) -> json11::Json {
        if (value.is_string() && ids.count(value.string_value())) return ids.at(value.string_value());
        if (value.is_object()) { auto object = value.object_items(); for (auto &[_, child] : object) child = remap(child); return object; }
        if (value.is_array()) { auto array = value.array_items(); for (auto &child : array) child = remap(child); return array; }
        return value;
      };
      copy["dock"] = remap(copy["dock"]);
      copy["panes"] = panes;
      pages.push_back(copy);
      document["pages"] = pages;
      document["active_page"] = (int)pages.size() - 1;
      restoreWorkspace(document);
    }
    std::string name = tabbar_.tabText(tabbar_.currentIndex());
    if (inputText("Page name", &name)) tabbar_.setTabText(tabbar_.currentIndex(), name);
  }));
  items.push_back(toolbarMenu("functions", "Functions", "Python functions", [this]() {
    if (dropdown::Item("New function...")) editEquation("");
    for (const auto &[id, equation] : equations_) {
      if (dropdown::BeginMenu(equation.name.c_str())) {
        if (dropdown::Item("Edit...")) editEquation(id);
        if (dropdown::Item("Plot")) { createChart()->addSource("equation/" + id); updateState(); }
        if (auto it = session.diagnostics().find(id); it != session.diagnostics().end()) ImGui::TextWrapped("%s", it->second.c_str());
        dropdown::EndMenu();
      }
    }
  }));

  // the spacer right aligns the rest
  const size_t spacer_index = items.size();
  size_t slider_index = (size_t)-1;
  const std::string range_lb = is_zoomed ? std::string() : "Plot range: " + utils::formatSeconds(max_chart_range_);
  std::string reset_zoom_text;
  if (!is_zoomed) {
    // the range label and the slider are one unit: drawn inline and moved to the overflow menu together
    slider_index = items.size();
    const float label_width = ImGui::CalcTextSize(range_lb.c_str()).x + ImGui::GetStyle().ItemInnerSpacing.x;
    items.push_back({label_width + slider_width, [this, &range_lb, &slider_width]() {
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(range_lb.c_str());
      ImGui::SameLine(0.0f, ImGui::GetStyle().ItemInnerSpacing.x);
      // Restore the slider width in overflow; the toolbar may have shrunk it.
      const bool in_menu = ImGui::GetCurrentWindow()->Flags & ImGuiWindowFlags_Popup;
      const float width = in_menu ? std::max(ImGui::GetContentRegionAvail().x, 150.0f) : slider_width;
      if (range_slider_.draw("##range_slider", width)) setMaxChartRange(range_slider_.value());
      ImGui::SetItemTooltip("Set the chart range");
    }});
  } else {
    const auto &range = *can->timeRange();
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f-%.2f", range.first, range.second);
    reset_zoom_text = std::string("Reset zoom: ") + buf;
    // The undo/redo/reset buttons form one group. The reset button has a fixed width in the mono font,
    // sized for the longest range the stream can show, so its neighbors do not shift as the range changes.
    const int digits = std::max({1, (int)std::to_string((long long)can->maxSeconds()).size(), (int)std::to_string((long long)range.second).size()});
    const std::string widest = std::string(digits, '0') + ".00";
    pushMonoFont(ImGui::GetFontSize());
    const float reset_zoom_width = iconTextButtonWidth(icon::ZOOM_OUT, "Reset zoom: " + widest + "-" + widest);
    popMonoFont();
    items.push_back(toolbarTextAction("undo_zoom", "Undo Zoom", [this]() { zoom_undo_stack_.undo(); }, zoom_undo_stack_.canUndo()));
    items.push_back(toolbarTextAction("redo_zoom", "Redo Zoom", [this]() { zoom_undo_stack_.redo(); }, zoom_undo_stack_.canRedo()));
    items.push_back({reset_zoom_width, [this, &reset_zoom_text, reset_zoom_width]() {
      pushMonoFont(ImGui::GetFontSize());
      const bool clicked = iconTextButton("reset_zoom_btn", icon::ZOOM_OUT, reset_zoom_text, reset_zoom_width);
      popMonoFont();
      if (clicked) zoomReset();
      ImGui::SetItemTooltip("Reset Zoom");
    }});
  }
  items.push_back(toolbarTextAction("remove_all_btn", "Clear Plots", [this]() { removeAll(); }, !charts_.empty()));

  // the slider shrinks first, the buttons stay pinned to the right edge
  if (slider_index != (size_t)-1) {
    const float shrink = std::min(slider_width - MIN_RANGE_SLIDER_WIDTH, toolbarWidth(items, spacer_index) - ImGui::GetContentRegionAvail().x);
    if (shrink > 0.0f) {
      slider_width -= shrink;
      items[slider_index].width -= shrink;
    }
  }
  drawToolbar(items, spacer_index);
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

ChartView *ChartsWidget::createChart(int pos) {
  auto chart = std::make_unique<ChartView>(can->timeRange().value_or(display_range_), this);
  ChartView *ptr = chart.get();
  pos = std::clamp(pos, 0, (int)charts_.size());
  charts_.insert(charts_.begin() + pos, std::move(chart));
  auto &current = currentCharts();
  current.insert(current.begin() + std::min(pos, (int)current.size()), ptr);
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
    auto &current = currentCharts();
    const int pos = std::find(current.begin(), current.end(), src_chart) - current.begin() + 1;
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
      ids += s.msg_id.toString() + "|" + s.name;
    }
    chart_ids.push_back(ids);
  }
  std::reverse(chart_ids.begin(), chart_ids.end());
  return chart_ids;
}

void ChartsWidget::restoreChartsFromIds(const std::vector<std::string> &chart_ids) {
  for (const auto &chart_id : chart_ids) {
    auto *chart = createChart();
    for (const auto &part : utils::split(chart_id, ',')) {
      const size_t sep = part.find('|');
      if (sep == std::string::npos) continue;
      if (auto id = MessageId::parse(part.substr(0, sep))) chart->addBinding(*id, part.substr(sep + 1));
    }
  }
  updateState();
}

void ChartsWidget::newChart() {
  execSignalSelector(std::make_unique<SignalSelector>("New Chart"), nullptr, [this](SignalSelector &dlg) {
    const auto &items = dlg.selectedItems();
    if (!items.empty()) {
      auto c = createChart();
      for (const auto &it : items) {
        if (it.path.empty()) c->addSignal(it.msg_id, it.sig);
        else c->addSource(it.path);
      }
      updateState();
    }
  });
}

void ChartsWidget::execSignalSelector(std::unique_ptr<SignalSelector> dlg, ChartView *owner, std::function<void(SignalSelector &)> accepted) {
  dlg->setSources(session.sources());
  signal_selector_ = std::move(dlg);
  signal_selector_owner_ = owner;
  signal_selector_accepted_ = std::move(accepted);
  signal_selector_->open();
}

void ChartsWidget::removeChart(ChartView *chart) {
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

void ChartsWidget::removeAll(bool reset_range) {
  while (tabbar_.count() > 1) {
    tabbar_.removeTab(1);
  }
  std::vector<ChartView *> all;
  for (auto &c : charts_) all.push_back(c.get());
  for (auto c : all) removeChart(c);
  tab_charts_.clear();
  if (reset_range) zoomReset();
}

void ChartsWidget::drawPageControls(const std::vector<ToolbarItem> &workspace_items) {
  deleted_charts_.clear();
  function_editor_.draw();
  drawToolBar(workspace_items);
  tabbar_.draw();
  if (signal_selector_ && !signal_selector_->draw()) {
    auto dlg = std::move(signal_selector_);
    auto accepted = std::move(signal_selector_accepted_);
    signal_selector_owner_ = nullptr;
    if (dlg->accepted() && accepted) accepted(*dlg);
  }
}

void ChartsWidget::draw() {
  browser_.draw(session, [this](const std::string &source, bool merge) {
    auto *chart = merge && !currentCharts().empty() ? currentCharts().front() : createChart();
    chart->addSource(source);
    updateState();
  });
}

void ChartsWidget::drawPanes() {
  any_plot_hovered_ = false;
  for (auto *chart : std::vector<ChartView *>(currentCharts())) {
    bool open = true;
    setNextPanelClass();
    ImGui::SetNextWindowSize(ImVec2(600, 350), ImGuiCond_FirstUseEver);
    if (beginPanel(chart->windowName().c_str(), &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse, false)) {
      chart->draw(ImGui::GetContentRegionAvail());
      any_plot_hovered_ |= chart->plotHovered();
      if (ImGui::IsMouseClicked(3) && ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows)) zoom_undo_stack_.undo();
    }
    ImGui::End();
    if (!open) removeChart(chart);
  }
  if (!any_plot_hovered_ && value_tip_visible_) showValueTip(-1);
}

json11::Json ChartsWidget::workspace() const {
  using J = json11::Json;
  J::array pages;
  for (int i = 0; i < tabbar_.count(); ++i) {
    J::array panes;
    auto it = tab_charts_.find(tabbar_.tabData(i));
    if (it != tab_charts_.end()) for (const auto *chart : it->second) panes.push_back(chart->definition());
    std::set<std::string> windows{"###MessagesPanel", "###CenterWidget", "###VideoPanel", "###ChartsWindow", "###WideCameraPanel", "###CabinCameraPanel"};
    for (const auto &pane : panes) windows.insert("###Chart/" + pane["id"].string_value());
    // A pane may close after this frame's dock capture. Never persist its stale tab.
    std::function<J(const J &)> prune = [&](const J &node) -> J {
      if (node.is_null()) return node;
      auto copy = node.object_items();
      if (node["panes"].is_array()) {
        J::array kept;
        for (const auto &name : node["panes"].array_items()) if (windows.count(name.string_value())) kept.push_back(name);
        copy["panes"] = kept;
        if (!node["selected"].is_null() && !windows.count(node["selected"].string_value())) copy["selected"] = "";
      }
      for (const auto *key : {"children", "floating"}) if (node[key].is_array()) {
        J::array entries;
        for (const auto &entry : node[key].array_items()) entries.push_back(prune(entry));
        copy[key] = entries;
      }
      if (!node["tree"].is_null()) copy["tree"] = prune(node["tree"]);
      return copy;
    };
    J::array widgets;
    auto enabled = page_widgets_.find(page_ids_.at(tabbar_.tabData(i)));
    if (enabled != page_widgets_.end()) for (const auto &id : enabled->second) widgets.push_back(id);
    pages.push_back(J::object{{"id", page_ids_.at(tabbar_.tabData(i))}, {"name", tabbar_.tabText(i)}, {"panes", panes},
                              {"widgets", widgets}, {"dock", prune(pageLayout(page_ids_.at(tabbar_.tabData(i))))}});
  }
  J::array equations;
  for (const auto &[id, e] : equations_) {
    J::array inputs;
    for (const auto &input : e.additional) inputs.push_back(input);
    equations.push_back(J::object{{"id", id}, {"name", e.name}, {"source", e.source}, {"globals", e.globals},
                                 {"function", e.function}, {"additional", inputs}, {"language", "python"}});
  }
  J view_range;
  if (auto range = can->timeRange()) view_range = J::array{range->first, range->second};
  return J::object{{"view_range", view_range}, {"relative_time", true}, {"equations", equations}, {"cabana_workspace", 1}, {"pages", pages}, {"active_page", tabbar_.currentIndex()}};
}

bool ChartsWidget::restoreWorkspace(const json11::Json &doc, bool restore_range) {
  if (!cabana::validateWorkspace(doc).empty()) return false;
  ++document_revision_;
  equations_.clear();
  for (const auto &item : doc["equations"].array_items()) {
    if (item["language"].string_value() != "python") return false;
    cabana::Equation equation{item["name"].string_value(), item["source"].string_value(), item["globals"].string_value(), item["function"].string_value(), {}};
    for (const auto &input : item["additional"].array_items()) equation.additional.push_back(input.string_value());
    equations_[item["id"].string_value()] = std::move(equation);
  }
  session.setEquations(equations_);
  removeAll(restore_range);
  for (int i = 0; i < doc["pages"].array_items().size(); ++i) {
    if (i) newTab();
    const auto &page = doc["pages"][i];
    if (!page["id"].string_value().empty()) page_ids_[tabbar_.tabData(i)] = page["id"].string_value();
    page_layouts_[activePageId()] = page["dock"];
    auto &widgets = page_widgets_[activePageId()];
    widgets.clear();
    if (page["widgets"].is_array()) {
      for (const auto &id : page["widgets"].array_items()) widgets.insert(id.string_value());
    } else {
      widgets = {"###MessagesPanel", "###CenterWidget", "###VideoPanel", "###ChartsWindow"};
    }
    for (const auto &pane : page["panes"].array_items()) createChart(charts_.size())->restoreDefinition(pane);
    tabbar_.setTabText(i, page["name"].string_value());
  }
  tabbar_.setCurrentIndex(std::clamp(doc["active_page"].int_value(), 0, tabbar_.count() - 1));
  auto range = doc["view_range"];
  if (!doc.object_items().count("view_range")) {
    const auto &saved = doc["pages"][tabbar_.currentIndex()]["panes"][0]["range"];
    if (saved["left"].is_number() && saved["right"].is_number()) range = json11::Json::array{saved["left"], saved["right"]};
  }
  if (restore_range && range.array_items().size() == 2 && range[1].number_value() > range[0].number_value()) {
    can->setTimeRange(std::make_pair(range[0].number_value(), range[1].number_value()));
  }
  updateState();
  return true;
}

std::vector<std::string> ChartsWidget::pageIds() const {
  std::vector<std::string> ids;
  for (int i = 0; i < tabbar_.count(); ++i) ids.push_back(page_ids_.at(tabbar_.tabData(i)));
  return ids;
}

json11::Json ChartsWidget::pageLayout(const std::string &id) const {
  auto it = page_layouts_.find(id);
  return it == page_layouts_.end() ? json11::Json() : it->second;
}

std::vector<std::string> ChartsWidget::paneWindows() const {
  std::vector<std::string> names;
  auto it = tab_charts_.find(tabbar_.tabData(tabbar_.currentIndex()));
  if (it != tab_charts_.end()) for (const auto *chart : it->second) names.push_back(chart->windowName());
  return names;
}

void ChartsWidget::editEquation(const std::string &existing_id) {
  std::random_device random;
  const std::string id = existing_id.empty() ? std::to_string(random()) + "-" + std::to_string(random()) : existing_id;
  cabana::Equation draft = existing_id.empty() ? cabana::Equation{"", "", "", "return value", {}} : equations_.at(id);
  function_editor_.open(draft, [this, id](cabana::Equation equation) {
    equations_[id] = std::move(equation);
    session.setEquations(equations_);
  });
}

void ChartsWidget::openWorkspace(const std::string &path) {
  std::ifstream input(path);
  std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  std::string error;
  auto doc = cabana::migrateWorkspace(json11::Json::parse(text, error));
  if (error.empty()) error = cabana::validateWorkspace(doc);
  if (!error.empty()) MessageBox::warning("Open Workspace", error);
  else restoreWorkspace(doc);
}

bool ChartsWidget::widgetVisible(const std::string &id) const {
  auto it = page_widgets_.find(activePageId());
  return it != page_widgets_.end() && it->second.count(id);
}

void ChartsWidget::setWidgetVisible(const std::string &id, bool visible) {
  auto &widgets = page_widgets_[activePageId()];
  if (visible) widgets.insert(id); else widgets.erase(id);
}

std::string ChartsWidget::addPlot() { return createChart()->windowName(); }
