#include "tools/cabana/ui/chart/chartswidget.h"

#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>

#include "common/util.h"
#include "json11/json11.hpp"
#include "tools/cabana/settings.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/chart/layout.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/ui/dialogs/messagebox.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/threadpool.h"
#include "tools/cabana/ui/util.h"

using json11::Json;

void ChartsWidget::fitTimeRange() {
  double min = std::numeric_limits<double>::max(), max = std::numeric_limits<double>::lowest();
  for (auto &c : charts_) for (const auto &s : c->signals()) {
    if (!s.visible || s.vals.empty()) continue;
    min = std::min(min, s.vals.front().x);
    max = std::max(max, s.vals.back().x);
  }
  if (max > min) zoom_undo_stack_.push(new ZoomCommand({min - can->timeline_offset, max - can->timeline_offset}));
}

std::string ChartsWidget::serializeLayout() const {
  chart::Layout layout{max_chart_range_, {}, equations_};
  for (const auto &c : charts_) {
    auto &saved = layout.charts.emplace_back(chart::LayoutChart{c->widget_id, c->title, (int)c->series_type_, c->limit_min, c->limit_max});
    for (const auto &s : c->sigs_) saved.signals.push_back({s.msg_id, s.signal_name, s.path, s.source_id, s.transform, s.visible});
  }
  return chart::dumpLayout(layout);
}

bool ChartsWidget::openLayout(const std::string &path) {
  if (!restoreLayout(util::read_file(path))) return false;
  if (std::any_of(charts_.begin(), charts_.end(), [](const auto &c) {
    return std::any_of(c->sigs_.begin(), c->sigs_.end(), [](const auto &s) { return !s.path.empty(); });
  })) showLogMessages();
  return true;
}

bool ChartsWidget::restoreLayout(const std::string &contents) {
  auto layout = chart::parseLayout(contents);
  if (!layout) {
    MessageBox::warning("Open Layout", "This is not a supported Cabana chart layout.");
    return false;
  }
  removeAll();
  equations_ = layout->equations;
  for (const auto &saved : layout->charts) {
    auto *c = charts_.emplace_back(std::make_unique<ChartView>(this)).get();
    // saved ids keep their window docking; charts without one get a new id below
    if (std::none_of(charts_.begin(), charts_.end(), [&](const auto &other) { return other->widget_id == saved.id; })) c->widget_id = saved.id;
    c->title = saved.title;
    c->limit_min = saved.y_min;
    c->limit_max = saved.y_max;
    c->setSeriesType((SeriesType)saved.type);
    for (const auto &s : saved.signals) {
      c->sigs_.push_back({.source_id = s.source_id.empty() ? can->source_id : s.source_id, .path = s.path, .msg_id = s.id,
                          .signal_name = s.name, .color = c->nextColor(), .visible = s.visible, .transform = s.transform});
    }
  }
  for (auto &c : charts_) if (c->widget_id.empty()) c->widget_id = newChartId();
  if (layout->range > 0) {
    max_chart_range_ = settings.chart_range = std::min(layout->range, range_slider_.maximum());
    range_slider_.setValue(max_chart_range_);
  }
  equationsChanged();  // loads the fields and functions; CAN signals load once resolved
  return true;
}

static std::shared_ptr<const cabana::Samples> findSamples(const cabana::FieldsSnapshot &fields, const std::string &path) {
  auto it = fields.find(path);
  return it == fields.end() ? nullptr : it->second;
}

// log fields start with '/', anything else is a function
std::shared_ptr<const cabana::Samples> ChartsWidget::fieldsSnapshot(const std::string &path, const std::string &source_id) const {
  if (path[0] != '/') {
    auto it = calculated_.find(source_id);
    return it == calculated_.end() ? nullptr : findSamples(it->second.values, path);
  }
  auto *source = sourceById(source_id);
  return source ? findSamples(source->fields, path) : nullptr;
}

std::string ChartsWidget::equationError(const std::string &source_id, const std::string &name) const {
  if (auto it = calculated_.find(source_id); it != calculated_.end()) {
    if (auto error = it->second.errors.find(name); error != it->second.errors.end()) return error->second;
  }
  return {};
}

void ChartsWidget::fieldsChanged(const std::string &source_id) {
  if (!equations_.empty()) dirty_sources_.insert(source_id);
  refreshFields(source_id, false);
}

// reloads the charted log fields and functions of a source, or only its functions
void ChartsWidget::refreshFields(const std::string &source_id, bool functions_only) {
  for (auto &c : charts_) {
    if (std::any_of(c->sigs_.begin(), c->sigs_.end(), [&](const auto &s) {
      return s.source_id == source_id && !s.path.empty() && (!functions_only || s.path[0] != '/');
    })) c->updateFields();
  }
}

// discards all results, including evaluations of previous definitions in flight, and evaluates every source again
void ChartsWidget::equationsChanged() {
  ++equation_revision_;
  calculated_.clear();
  for (auto &[_, browser] : browsers_) browser.dirty = true;
  for (auto *source : sources()) fieldsChanged(source->source_id);
}

void ChartsWidget::pollEquations() {
  if (equation_task_.valid()) {
    if (equation_task_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
    equation_task_.get();
    if (equation_result_->revision == equation_revision_ && !equation_result_->source_alive.expired()) {
      std::swap(calculated_[equation_result_->source_id], equation_result_->calculated);
      refreshFields(equation_result_->source_id, true);
    }
    ThreadPool::instance().run([retired = std::move(equation_result_)]() mutable { retired.reset(); });
  }
  if (dirty_sources_.empty()) return;
  auto *source = sourceById(*dirty_sources_.begin());
  dirty_sources_.erase(dirty_sources_.begin());
  if (!source) return;
  // retain the immutable inputs without copying samples on the UI thread
  cabana::FieldsSnapshot data;
  auto add = [&](const std::string &path) { if (auto samples = findSamples(source->fields, path)) data.emplace(path, samples); };
  for (const auto &e : equations_) {
    add(e.source);
    for (const auto &path : e.additional) add(path);
  }
  equation_result_ = std::make_shared<EquationResult>(EquationResult{{}, source->source_id, source->lifetime(), equation_revision_});
  equation_task_ = ThreadPool::instance().run([equations = equations_, data = std::move(data), result = equation_result_]() mutable {
    auto &errors = result->calculated.errors;
    auto ready = [&](const std::string &path) { auto it = data.find(path); return it != data.end() && !it->second->empty(); };
    // functions can use each other: each one is evaluated once all of its inputs are
    for (bool progress = true; progress;) {
      progress = false;
      for (const auto &e : equations) {
        if (data.count(e.name) || errors.count(e.name) || !ready(e.source) || !std::all_of(e.additional.begin(), e.additional.end(), ready)) continue;
        try { data[e.name] = std::make_shared<const cabana::Samples>(cabana::evaluateEquation(e, data)); }
        catch (const std::exception &error) { errors[e.name] = error.what(); }
        progress = true;
      }
    }
    for (const auto &e : equations) {
      if (auto samples = findSamples(data, e.name)) result->calculated.values.emplace(e.name, samples);
      else errors.try_emplace(e.name, "Waiting for its inputs, which must not depend on it");
    }
  });
}

void ChartsWidget::exportCsv() {
  // Snapshot the visible range now, so playback or later edits cannot change the export.
  std::ostringstream out;
  out.imbue(std::locale::classic());
  out << "chart,source,name,transform,scale,offset,window,time,value\n" << std::setprecision(17);
  const auto range = can->timeRange().value_or(display_range_);
  size_t rows = 0;
  for (size_t i = 0; i < charts_.size(); ++i) {
    for (const auto &s : charts_[i]->signals()) {
      if (!s.visible) continue;
      const auto prefix = std::to_string(i + 1) + ',' + chart::csvField(s.source_id + ":" + (s.path.empty() ? s.msg_id.toString() : "openpilot")) + ',' +
        chart::csvField(s.name()) + ',' + chart::csvField(chart::TRANSFORM_NAMES[(int)s.transform.type]) + ',';
      auto it = std::lower_bound(s.vals.begin(), s.vals.end(), range.first + can->timeline_offset, [](const auto &p, double t) { return p.x < t; });
      for (; it != s.vals.end() && it->x < range.second + can->timeline_offset; ++it, ++rows) {
        out << prefix << s.transform.scale << ',' << s.transform.offset << ',' << s.transform.window << ',' << it->x << ',' << it->y << '\n';
      }
    }
  }
  if (!rows) { MessageBox::information("Export CSV", "There are no visible samples in this time range."); return; }
  FileDialog::getSaveFileName("Export Visible Chart Data", settings.last_dir + "/charts.csv", ".csv", [contents = out.str()](const std::string &path) {
    if (!path.empty() && !(std::ofstream(path) << contents)) MessageBox::warning("Export CSV", "Could not write the chart data.");
  });
}

void ChartsWidget::drawSignalBrowser() {
  auto &browser = browsers_[can->source_id];
  auto &tree = browser.tree;
  const bool rebuild = browser.dirty || browser.field_count != can->fields.size();
  if (rebuild) {
    browser.dirty = false;
    browser.field_count = can->fields.size();
    std::vector<std::string> paths;
    std::unordered_set<std::string> functions;
    for (const auto &[path, _] : can->fields) paths.push_back(path);
    for (const auto &equation : equations_) { paths.push_back(equation.name); functions.insert(equation.name); }
    tree.rebuild(paths, functions);
  }
  ImGui::SetNextItemWidth(-1.0f);
  const bool filter_changed = inputText("##search_fields", &browser.filter, "Search openpilot messages...");
  if (filter_changed || rebuild) {
    tree.filter(browser.filter);
    browser.search_expanded.clear();
    for (const auto &node : tree.nodes) {
      if (!browser.filter.empty() && node.matches && !node.children.empty()) browser.search_expanded.insert(node.key);
    }
  }
  auto &expanded = browser.filter.empty() ? browser.expanded : browser.search_expanded;
  ImGui::PushTextWrapPos(0.0f);
  ImGui::TextDisabled("Double-click to plot · Drag onto a chart to compare");
  ImGui::PopTextWrapPos();
  ImGui::AlignTextToFramePadding();
  ImGui::Text("%zu fields", tree.nodes[0].matches);
  alignRight(iconButtonWidth() * 2 + ImGui::GetStyle().ItemInnerSpacing.x);
  if (iconButton("expand_signals", icon::PLUS_LG, "Expand all")) {
    for (const auto &node : tree.nodes) {
      if (node.matches && !node.children.empty()) expanded.insert(node.key);
    }
  }
  ImGui::SameLine(0, ImGui::GetStyle().ItemInnerSpacing.x);
  if (iconButton("collapse_signals", icon::ARROWS_COLLAPSE, "Collapse all")) expanded.clear();
  if (tree.nodes[0].children.empty()) ImGui::TextWrapped("Open a route or start a stream to browse openpilot messages.");
  else if (!tree.nodes[0].matches) {
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextDisabled("No fields match your search.");
    ImGui::PopTextWrapPos();
  }
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, ImGui::GetStyle().WindowPadding.y));
  const bool browser_visible = ImGui::BeginChild("signal_browser_list", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding,
                                                ImGuiWindowFlags_HorizontalScrollbar);
  ImGui::PopStyleVar();
  if (browser_visible) {
    if (filter_changed) ImGui::SetScrollY(0);
    const auto rows = tree.visible(expanded);
    ImGuiListClipper clipper;
    clipper.Begin(rows.size(), ImGui::GetTextLineHeightWithSpacing());
    while (clipper.Step()) for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
      const auto &node = tree.nodes[rows[i]];
      const bool branch = !node.children.empty();
      const std::string label = chart::SignalTree::isIndex(node.name) ? tree.nodes[node.parent].name + "/" + node.name : node.name;
      ImGui::PushID(node.key.c_str());
      const float indent = node.depth * ImGui::GetStyle().IndentSpacing * 0.5f;
      if (indent > 0) ImGui::Indent(indent);
      ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_SpanAvailWidth;
      if (!branch) flags |= ImGuiTreeNodeFlags_Leaf;
      ImGui::SetNextItemOpen(branch && expanded.count(node.key), ImGuiCond_Always);
      const bool open = ImGui::TreeNodeEx("node", flags, "%s", label.c_str());
      if (branch && ImGui::IsItemToggledOpen()) {
        if (open) expanded.insert(node.key);
        else expanded.erase(node.key);
      }
      if (node.signal_matches) {
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && !ImGui::IsItemToggledOpen()) newChart()->addFields(can->source_id, node.path);
        if (ImGui::IsItemHovered()) {
          const auto points = fieldsSnapshot(node.path, can->source_id);
          const double time = can->beginMonoTime() * 1e-9 + can->currentSec();
          if (points && !points->empty()) ImGui::SetTooltip("%s\nValue: %.8g", node.path.c_str(), cabana::nearestValue(*points, time));
          else ImGui::SetTooltip("%s", node.path.c_str());
        }
        if (ImGui::BeginDragDropSource()) {
          const auto payload = Json(Json::object{{"source", can->source_id}, {"path", node.path}}).dump();
          ImGui::SetDragDropPayload("CABANA_SIGNAL", payload.c_str(), payload.size() + 1);
          ImGui::TextUnformatted(node.path.c_str());
          ImGui::EndDragDropSource();
        }
      } else if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s\n%zu fields", node.key.c_str(), node.matches);
      }
      if (indent > 0) ImGui::Unindent(indent);
      ImGui::PopID();
    }
  }
  ImGui::EndChild();
}
