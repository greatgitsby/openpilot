#include "tools/cabana/ui/analysis.h"
#include "tools/cabana/ui/app.h"
#include "tools/cabana/settings.h"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>
#include "implot.h"
#include "tools/cabana/analysis/python.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/threadpool.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/streams/replaystream.h"
#include "tools/cabana/streams/logfilestream.h"
#include "tools/cabana/utils/util.h"
#include "common/util.h"

using namespace cabana::analysis;
using J = json11::Json;

namespace {

// Palette from commaai/connect src/colors.js and src/theme.js (7091050).
// Connect defines dark mode; light mode uses its lightGrey and lightBlue families.
// Secondary text stays brighter than Connect's placeholders for dense signal tables.
struct AnalysisStyle {
  int colors = 0;
  int plot_colors = 0;
  AnalysisStyle() {
    const bool dark = isDarkTheme();
    auto color = [&](ImGuiCol slot, unsigned night, unsigned day) {
      unsigned rgb = dark ? night : day;
      ImGui::PushStyleColor(slot, ImVec4(((rgb >> 16) & 255) / 255.f, ((rgb >> 8) & 255) / 255.f, (rgb & 255) / 255.f, 1));
      ++colors;
    };
    color(ImGuiCol_Text, 0xf8f9f9, 0x1e2224);
    color(ImGuiCol_TextDisabled, 0xb8c0c4, 0x535f64);
    color(ImGuiCol_ChildBg, 0x30373b, 0xffffff);
    color(ImGuiCol_PopupBg, 0x30373b, 0xffffff);
    color(ImGuiCol_Border, 0x65737a, 0x98a3a9);
    color(ImGuiCol_Separator, 0x4b5559, 0xcdd3d6);
    color(ImGuiCol_FrameBg, 0x1e2224, 0xf8f9f9);
    color(ImGuiCol_FrameBgHovered, 0x394044, 0xeeeff0);
    color(ImGuiCol_FrameBgActive, 0x424a4f, 0xddeef9);
    color(ImGuiCol_Button, 0x424a4f, 0xe3e6e8);
    color(ImGuiCol_ButtonHovered, 0x535f64, 0xd8dcdf);
    color(ImGuiCol_ButtonActive, 0x175886, 0xbcddf4);
    color(ImGuiCol_Header, 0x175886, 0xddeef9);
    color(ImGuiCol_HeaderHovered, 0x424a4f, 0xeeeff0);
    color(ImGuiCol_HeaderActive, 0x1c6ea8, 0xbcddf4);
    color(ImGuiCol_CheckMark, 0x57a9e3, 0x1c6ea8);
    color(ImGuiCol_NavCursor, 0x57a9e3, 0x1c6ea8);
    color(ImGuiCol_Tab, 0x272c2f, 0xe3e6e8);
    color(ImGuiCol_TabHovered, 0x424a4f, 0xddeef9);
    color(ImGuiCol_TabSelected, 0x30373b, 0xffffff);
    color(ImGuiCol_TabSelectedOverline, 0x57a9e3, 0x1c6ea8);
    color(ImGuiCol_TableHeaderBg, 0x424a4f, 0xd8dcdf);
    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, ImVec4(dark ? 1.f : 0.f, dark ? 1.f : 0.f, dark ? 1.f : 0.f, dark ? 0.065f : 0.045f)); ++colors;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 10));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9, 5));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 8));
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(6, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_TabRounding, 4.f);
    auto plot = [&](ImPlotCol slot, ImVec4 value) { ImPlot::PushStyleColor(slot, value); ++plot_colors; };
    plot(ImPlotCol_FrameBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
    plot(ImPlotCol_PlotBg, dark ? colorRgb(21, 24, 25) : colorRgb(248, 249, 249));
    plot(ImPlotCol_PlotBorder, ImGui::GetStyleColorVec4(ImGuiCol_Border));
    plot(ImPlotCol_AxisText, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    plot(ImPlotCol_AxisGrid, dark ? colorRgb(101, 115, 122, .45f) : colorRgb(152, 163, 169, .4f));
    plot(ImPlotCol_LegendBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
    plot(ImPlotCol_LegendBorder, ImGui::GetStyleColorVec4(ImGuiCol_Border));
  }
  ~AnalysisStyle() { ImPlot::PopStyleColor(plot_colors); ImGui::PopStyleVar(8); ImGui::PopStyleColor(colors); }
};

void sectionTitle(const char *title) {
  ImGui::PushFont(boldFont(), ImGui::GetFontSize());
  ImGui::TextUnformatted(title);
  ImGui::PopFont();
}

// Keep saved curve colors intact, adapting only their display brightness.
ImVec4 analysisCurveColor(unsigned rgb) {
  ImVec4 color(((rgb >> 16) & 255) / 255.f, ((rgb >> 8) & 255) / 255.f, (rgb & 255) / 255.f, 1);
  auto luminance = [](const ImVec4 &c) {
    auto linear = [](float v) { return v <= .04045f ? v / 12.92f : std::pow((v + .055f) / 1.055f, 2.4f); };
    return .2126f * linear(c.x) + .7152f * linear(c.y) + .0722f * linear(c.z);
  };
  for (int i = 0; i < 24; ++i) {
    float light = luminance(color);
    if (isDarkTheme() ? light >= .25f : light <= .23f) break;
    const float target = isDarkTheme() ? 1.f : 0.f;
    color.x += (target - color.x) * .1f; color.y += (target - color.y) * .1f; color.z += (target - color.z) * .1f;
  }
  return color;
}

}  // namespace

static J serializeInputs(const std::map<std::string, Channel> &channels, double origin) {
  J::object result;
  for (const auto &[name, data] : channels) {
    J::array points; points.reserve(data.samples().size());
    for (const auto &point : data.samples()) points.push_back(J::array{point.time - origin, point.value});
    result[name] = std::move(points);
  }
  return result;
}

AnalysisWorkspace::AnalysisWorkspace() {
  connections_.push_back(dbc()->fileChanged.connect([this]() { dbc_dirty_ = true; }));
  connections_.push_back(dbc()->signalAdded.connect([this](auto, auto) { dbc_dirty_ = true; }));
  connections_.push_back(dbc()->signalRemoved.connect([this](auto) { dbc_dirty_ = true; }));
  connections_.push_back(dbc()->msgRemoved.connect([this](auto) { dbc_dirty_ = true; }));
  connections_.push_back(dbc()->signalUpdated.connect([this](auto) { dbc_dirty_ = true; }));
  connections_.push_back(dbc()->msgUpdated.connect([this](auto) { dbc_dirty_ = true; }));
  connections_.push_back(can->eventsMerged.connect([this](auto &) { dbc_dirty_ = true; }));
  const auto autosave = utils::configPath() / "cabana-analysis.json";
  if (analysis_launch.layout.empty() && std::filesystem::exists(autosave)) { load(autosave.string()); path_.clear(); }
  checkpoint();
}
AnalysisWorkspace::~AnalysisWorkspace() {
  alive_.reset();
  if (range_initialized_) { layout_.range_set = true; layout_.x_min = x_min_; layout_.x_max = x_max_; }
  save((utils::configPath() / "cabana-analysis.json").string());
}

const Channel *AnalysisWorkspace::channel(const std::string &name) const {
  auto source = can_sources_.find(name);
  if (source != can_sources_.end() && !decoded_can_.count(name) && !can_jobs_.count(name)) {
    const auto &[id, signal, sent] = source->second;
    std::shared_ptr<const std::vector<const CanEvent *>> events;
    std::vector<SentFrame> sent_frames;
    if (sent) {
      for (const auto &frame : can->analysis_data.sent_frames)
        if (frame.bus == id.source && frame.address == id.address) sent_frames.push_back(frame);
    } else {
      auto &snapshot = can_event_snapshots_[id];
      if (!snapshot) {
        const auto &history = can->events(id);
        auto first = history.begin();
        if (can->liveStreaming()) first = std::lower_bound(first, history.end(), can->analysis_data.first,
          [](const auto *event, double time) { return event->mono_time * 1e-9 < time; });
        snapshot = std::make_shared<const std::vector<const CanEvent *>>(first, history.end());
      }
      events = snapshot;
    }
    std::optional<cabana::Signal> multiplexor;
    if (signal->multiplexor) multiplexor = *signal->multiplexor;
    auto task = std::make_shared<std::packaged_task<Channel()>>(
      [signal_spec = *signal, multiplexor, events, sent_frames = std::move(sent_frames), storage = can->eventStorage()]() mutable {
        signal_spec.multiplexor = multiplexor ? &*multiplexor : nullptr;
        Channel result;
        auto &points = result.editSamples();
        points.reserve(events ? events->size() : sent_frames.size());
        if (events) for (const auto *event : *events) {
          double value;
          if (signal_spec.getValue(event->dat, event->size, &value)) points.push_back({event->mono_time * 1e-9, value});
        }
        for (const auto &frame : sent_frames) {
          double value;
          if (signal_spec.getValue(frame.bytes.data(), frame.bytes.size(), &value)) points.push_back({frame.time, value});
        }
        for (const auto &label : signal_spec.val_desc) result.labels[label.first] = label.second;
        return result;
      });
    can_jobs_.emplace(name, CanJob{can_revision_, task->get_future()});
    ThreadPool::instance().run([task] { (*task)(); });
  }
  for (const std::map<std::string, Channel> *collection : {&custom_channels_, static_cast<const std::map<std::string, Channel> *>(&can_channels_), static_cast<const std::map<std::string, Channel> *>(&can->analysis_data.channels)}) {
    auto it = collection->find(name);
    if (it != collection->end()) return &it->second;
  }
  return nullptr;
}
void AnalysisWorkspace::refreshCan() {
  if (data_revision_ != can->analysis_data.revision) { data_revision_ = can->analysis_data.revision; dbc_dirty_ = true; }
  if (!dbc_dirty_) return;
  dbc_dirty_ = false; ++can_revision_; can_sources_.clear(); decoded_can_.clear();
  auto retired_events = std::move(can_event_snapshots_);
  can_event_snapshots_.clear();
  ThreadPool::instance().run([retired_events = std::move(retired_events)] {});
  auto add = [&](MessageId id, bool sent) {
    auto msg = dbc()->msg(id);
    if (!msg) return;
    for (auto signal : msg->getSignals()) {
      std::string name = (sent ? "/sendcan/" : "/can/") + std::to_string(id.source) + "/" + msg->name + "/" + signal->name;
      auto &destination = can_channels_[name];
      destination.labels.clear();
      for (auto &label : signal->val_desc) destination.labels[label.first] = label.second;
      can_sources_[name] = {id, signal, sent};
    }
  };
  for (auto &[id, events] : can->eventsMap()) add(id, false);
  std::set<MessageId> sent_ids;
  for (auto &frame : can->analysis_data.sent_frames) sent_ids.insert({.source = frame.bus, .address = frame.address});
  for (auto id : sent_ids) add(id, true);
  for (auto it = can_channels_.begin(); it != can_channels_.end();) {
    if (!can_sources_.count(it->first)) it = can_channels_.erase(it); else ++it;
  }
}
void AnalysisWorkspace::pollCan() {
  for (auto it = can_jobs_.begin(); it != can_jobs_.end();) {
    if (it->second.result.wait_for(std::chrono::seconds(0)) != std::future_status::ready) { ++it; continue; }
    auto result = it->second.result.get();
    if (it->second.revision == can_revision_ && can_sources_.count(it->first)) {
      std::swap(can_channels_[it->first], result);
      decoded_can_.insert(it->first); ++can_result_revision_;
    }
    ThreadPool::instance().run([retired = std::move(result)] {});
    it = can_jobs_.erase(it);
  }
}

void AnalysisWorkspace::checkpoint() {
  std::string next = layout_.json().dump();
  if (history_pos_ >= 0 && history_[history_pos_] == next) return;
  history_.resize(history_pos_ + 1); history_.push_back(next);
  if (history_.size() > 100) history_.erase(history_.begin());
  history_pos_ = history_.size() - 1;
}
void AnalysisWorkspace::undo(int direction) {
  int next = history_pos_ + direction;
  if (next < 0 || next >= int(history_.size())) return;
  std::string error;
  layout_ = Layout::parse(J::parse(history_[next], error)); history_pos_ = next; select_tab_ = true; range_initialized_ = layout_.range_set; if (layout_.range_set) { x_min_ = layout_.x_min; x_max_ = layout_.x_max; } formula_signature_.clear(); custom_channels_.clear(); browser_dirty_ = true;
}
void AnalysisWorkspace::load(const std::string &path) {
  try {
    std::string error;
    std::string resolved = path;
    if (!std::filesystem::is_regular_file(resolved)) resolved = (executableDir() / "layouts" / (path + ".json")).string();
    auto parsed = std::filesystem::path(resolved).extension() == ".xml"
      ? cabana::analysis::pythonTask((executableDir() / "analysis/import_layout.py").string(), J::object{{"path", resolved}})
      : J::parse(util::read_file(resolved), error);
    if (!error.empty()) throw std::runtime_error(error);
    auto next = Layout::parse(parsed);
    layout_ = std::move(next);
    select_tab_ = true; range_initialized_ = layout_.range_set;
    if (layout_.range_set) { x_min_ = layout_.x_min; x_max_ = layout_.x_max; }
    path_ = resolved; checkpoint(); visible = true; custom_channels_.clear(); browser_dirty_ = true; formula_signature_.clear();
    error_.clear();
  } catch (const std::exception &e) { error_ = "Load layout: " + std::string(e.what()); }
}
void AnalysisWorkspace::save(const std::string &path) {
  if (range_initialized_) { layout_.range_set = true; layout_.x_min = x_min_; layout_.x_max = x_max_; }
  std::error_code directory_error;
  std::filesystem::create_directories(std::filesystem::path(path).parent_path(), directory_error);
  std::ofstream file(path + ".tmp"); file << layout_.json().dump() << '\n'; file.close();
  if (!file) { error_ = "Unable to save layout: " + path; return; }
  std::error_code error; std::filesystem::rename(path + ".tmp", path, error);
  if (error) error_ = error.message(); else { path_ = path; error_.clear(); }
}
std::string AnalysisWorkspace::state() const {
  size_t sample_count = 0;
  for (auto &[_, data] : can->analysis_data.channels) sample_count += data.samples().size();
  return J(J::object{{"data_first", can->analysis_data.first}, {"data_last", can->analysis_data.last}, {"samples", double(sample_count)}, {"layout", layout_.json()}, {"layout_path", path_}, {"channels", int(can->analysis_data.channels.size() + can_channels_.size())},
    {"logs", int(can->analysis_data.logs.size())}, {"thumbnails", int(can->analysis_data.thumbnails.size())},
    {"selected", selected_}, {"ctrl", ImGui::GetIO().KeyCtrl}, {"mouse", J::array{ImGui::GetIO().MousePos.x, ImGui::GetIO().MousePos.y}}, {"hovered_window", GImGui->HoveredWindow ? GImGui->HoveredWindow->Name : ""}, {"texts", test_texts_}, {"items", test_items_}, {"plots", test_plots_}, {"filter", filter_}, {"preview_samples", int(preview_.size())},
    {"custom_channels", int(custom_channels_.size())}, {"evaluating", evaluation_.valid()}, {"fps", ImGui::GetIO().Framerate},
    {"cursor", can->currentSec()}, {"x_min", x_min_}, {"x_max", x_max_}, {"error", error_}}).dump();
}
void AnalysisWorkspace::menu() {
  ImGui::MenuItem("Analysis workspace", nullptr, &visible);
  if (ImGui::BeginMenu("Presets")) {
    std::error_code error;
    for (auto &file : std::filesystem::directory_iterator(executableDir() / "layouts", error))
      if (file.path().extension() == ".json" && ImGui::MenuItem(file.path().stem().c_str())) load(file.path().string());
    ImGui::EndMenu();
  }
  if (ImGui::MenuItem("New analysis layout")) { layout_ = {}; custom_channels_.clear(); browser_dirty_ = true; range_initialized_ = false; checkpoint(); visible = true; }
  if (ImGui::MenuItem("Reload saved layout", nullptr, false, !path_.empty())) load(path_);
  if (ImGui::MenuItem("Load analysis layout...")) FileDialog::getOpenFileName("Load analysis layout", "", "", utils::guarded(alive_, [this](const std::string &p) { if (!p.empty()) load(p); }));
  if (ImGui::MenuItem("Save analysis layout")) {
    if (!path_.empty()) save(path_);
    else FileDialog::getSaveFileName("Save analysis layout", "analysis.json", ".json", utils::guarded(alive_, [this](const std::string &p) { if (!p.empty()) save(p); }));
  }
  if (ImGui::MenuItem("Save analysis layout as...")) FileDialog::getSaveFileName("Save analysis layout", "analysis.json", ".json", utils::guarded(alive_, [this](const std::string &p) { if (!p.empty()) save(p); }));
  if (ImGui::MenuItem("Undo analysis change", nullptr, false, history_pos_ > 0)) undo(-1);
  if (ImGui::MenuItem("Redo analysis change", nullptr, false, history_pos_ + 1 < int(history_.size()))) undo(1);
  if (ImGui::MenuItem("Edit layout JSON...")) { layout_source_ = layout_.json().dump(); layout_editor_ = true; visible = true; }
  ImGui::MenuItem("Show FPS", nullptr, &fps_);
  if (ImGui::MenuItem("Clear map cache", nullptr, false, !map_request_.valid())) {
    std::error_code error; std::filesystem::remove_all(utils::configPath() / "cabana-map-cache", error); map_key_.clear(); map_roads_.clear();
    if (error) error_ = error.message();
  }
}
void AnalysisWorkspace::editMenu() {
  if (ImGui::MenuItem("Undo layout change", "Ctrl+Z", false, history_pos_ > 0)) undo(-1);
  if (ImGui::MenuItem("Redo layout change", "Ctrl+Shift+Z", false, history_pos_ + 1 < int(history_.size()))) undo(1);
}
void AnalysisWorkspace::toolbar() {
  if (button("< Step")) { can->pause(true); can->seekTo(can->currentSec() - step_); }
  ImGui::SameLine(); if (button("Step >")) { can->pause(true); can->seekTo(can->currentSec() + step_); }
  ImGui::SameLine(); ImGui::SetNextItemWidth(65); ImGui::InputDouble("Step", &step_, 0, 0, "%.2f"); step_ = std::max(0.001, step_);
  ImGui::SameLine(); checkBox("Loop range", &loop_); record("Loop");
  ImGui::SameLine(); checkBox("Follow", &follow_);
  ImGui::SameLine(); if (button("Time range")) ImGui::OpenPopup("time_range");
  if (ImGui::BeginPopup("time_range")) {
    double left = x_min_, right = x_max_;
    ImGui::InputDouble("Start (s)", &left); ImGui::InputDouble("End (s)", &right);
    if (std::isfinite(left) && std::isfinite(right) && left < right) { x_min_ = left; x_max_ = right; }
    if (button("Apply range")) { layout_.range_set = true; layout_.x_min = x_min_; layout_.x_max = x_max_; checkpoint(); ImGui::CloseCurrentPopup(); }
    ImGui::EndPopup();
  }
  ImGui::SameLine(); if (button("Reset view")) { x_min_ = can->minSeconds(); x_max_ = std::max(x_min_ + 1, can->maxSeconds()); can->setTimeRange(std::nullopt); }
  if (can->liveStreaming()) {
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputDouble("Buffer (s)", &can->analysis_buffer_seconds);
    can->analysis_buffer_seconds = std::clamp(can->analysis_buffer_seconds, 1.0, 86400.0);
  }
  double current = can->currentSec();
  if (loop_ && current >= x_max_) can->seekTo(x_min_);
  if (follow_) { double width = x_max_ - x_min_; x_max_ = std::max(width, current); x_min_ = x_max_ - width; }
}
void AnalysisWorkspace::addSelected(Pane &p) {
  static const char *colors[] = {"#36a9e1", "#ee7744", "#52bd77", "#cb62c4", "#ddbb33"};
  for (auto &name : selection_) {
    if (std::none_of(p.curves.begin(), p.curves.end(), [&](auto &c) { return c.name == name; })) {
      Curve c; c.name = name; c.color = colors[p.curves.size() % 5]; p.curves.push_back(c);
    }
  }
  checkpoint();
}
void AnalysisWorkspace::browser() {
  sectionTitle("Signals");
  if (focus_search_) { ImGui::SetKeyboardFocusHere(); focus_search_ = false; }
  ImGui::SetNextItemWidth(-FLT_MIN);
  inputText("##signal_search", &filter_, "Search signals..."); record("Search signals");
  checkBox("Show deprecated", &deprecated_); record("Show deprecated");
  ImGui::SameLine(); checkBox("Tree", &tree_browser_);
  if (button("Custom series...")) { formula_open_ = true; formula_.source = selected_; }
  if (!formula_errors_.empty()) {
    if (ImGui::TreeNode("Series errors")) { for (auto &[name, error] : formula_errors_) ImGui::TextWrapped("%s: %s", name.c_str(), error.c_str()); ImGui::TreePop(); }
  }
  ImGui::TextDisabled("Double-click to plot");
  if (ImGui::IsItemHovered()) ImGui::SetTooltip("Ctrl-click to select multiple signals. Drag signals onto a plot.");
  ImGui::BeginChild("series_list");
  if (ImGui::BeginTable("signals", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg)) {
  ImGui::TableSetupColumn("Signal", ImGuiTableColumnFlags_WidthStretch);
  ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 75);
  ImGui::TableHeadersRow();
  const size_t channel_count = can->analysis_data.channels.size() + can_channels_.size() + custom_channels_.size();
  if (browser_dirty_ || browser_channel_count_ != channel_count || browser_can_revision_ != can_revision_ ||
      browser_filter_ != filter_ || browser_tree_ != tree_browser_ || browser_deprecated_ != deprecated_) {
    browser_dirty_ = false; browser_channel_count_ = channel_count; browser_can_revision_ = can_revision_;
    browser_filter_ = filter_; browser_tree_ = tree_browser_; browser_deprecated_ = deprecated_;
  std::map<std::string, bool> entries;
  for (auto *collection : {&can->analysis_data.channels, &can_channels_, &custom_channels_}) {
    for (auto &[name, data] : *collection) {
      if ((!deprecated_ && (name.find("DEPRECATED") != std::string::npos || name.find("/deprecated/") != std::string::npos)) || (!filter_.empty() && name.find(filter_) == std::string::npos)) continue;
      entries[name] = true;
    }
  }
  browser_rows_.clear();
  bool hierarchy = tree_browser_ && filter_.empty();
  if (hierarchy) {
    auto nodes = entries;
    for (auto &[name, _] : entries) {
      for (size_t pos = name.find('/', 1); pos != std::string::npos; pos = name.find('/', pos + 1)) nodes.emplace(name.substr(0, pos), false);
    }
    for (auto &[name, data] : nodes) {
      bool ancestors_expanded = true;
      for (size_t pos = name.find('/', 1); pos != std::string::npos; pos = name.find('/', pos + 1)) {
        if (!expanded_paths_.count(name.substr(0, pos))) { ancestors_expanded = false; break; }
      }
      if (ancestors_expanded) browser_rows_.emplace_back(name, data);
    }
  } else browser_rows_.assign(entries.begin(), entries.end());
  }
  bool hierarchy = tree_browser_ && filter_.empty();
  const auto &rows = browser_rows_;
  ImGuiListClipper clip; clip.Begin(rows.size());
  while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
    const auto &[name, leaf] = rows[i];
    ImGui::TableNextRow(); ImGui::TableNextColumn();
    int depth = hierarchy ? std::max(0, int(std::count(name.begin(), name.end(), '/')) - 1) : 0;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + depth * 10);
    if (!leaf) {
      std::string label = (expanded_paths_.count(name) ? "v " : "> ") + name.substr(name.find_last_of('/') + 1) + "##" + name;
      if (ImGui::Selectable(label.c_str())) { browser_dirty_ = true; if (expanded_paths_.count(name)) expanded_paths_.erase(name); else expanded_paths_.insert(name); }
      record(name); ImGui::TableNextColumn(); continue;
    }
    auto data = channel(name);
    if (!data) { browser_dirty_ = true; continue; }
    std::string display = hierarchy ? name.substr(name.find_last_of('/') + 1) + "##" + name : name;
    if (ImGui::Selectable(display.c_str(), selection_.count(name), ImGuiSelectableFlags_AllowDoubleClick)) {
      if (!ImGui::GetIO().KeyCtrl) selection_.clear();
      if (selection_.count(name)) selection_.erase(name); else selection_.insert(name);
      selected_ = name;
      if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        auto *target = &layout_.tabs[layout_.active].root;
        while (!target->children.empty()) target = &target->children.front();
        addSelected(*target);
      }
    }
    record(name);
    if (ImGui::BeginDragDropSource()) {
      if (!selection_.count(name)) { selection_.clear(); selection_.insert(name); }
      ImGui::SetDragDropPayload("CABANA_ANALYSIS", "", 1); ImGui::Text("%zu signals", selection_.size()); ImGui::EndDragDropSource();
    }
    if (ImGui::IsItemHovered()) {
      auto value = data->at(origin() + can->currentSec());
      if (value) {
        auto label = data->labels.find(int(*value));
        ImGui::SetTooltip("%s\n%.9g %s\n%zu samples", name.c_str(), *value, label == data->labels.end() ? "" : label->second.c_str(), data->samples().size());
      }
    }
    ImGui::TableNextColumn();
    if (auto value = data->at(origin() + can->currentSec())) {
      auto label = data->labels.find(int(*value));
      if (label == data->labels.end()) ImGui::Text("%.6g", *value); else ImGui::TextUnformatted(label->second.c_str());
    } else ImGui::TextUnformatted("--");
  }
  ImGui::EndTable();
  }
  ImGui::EndChild();
}
void AnalysisWorkspace::plot(Pane &p, ImVec2 size) {
  ImPlot::SetNextAxisLimits(ImAxis_X1, x_min_, x_max_, ImPlotCond_Always);
  bool valid_limits = std::isfinite(p.y_min) && std::isfinite(p.y_max) && (!p.y_min_set || !p.y_max_set || p.y_min < p.y_max);
  if (!valid_limits) { error_ = "Y limits must be finite and minimum must be below maximum"; ImPlot::SetNextAxisToFit(ImAxis_Y1); }
  else if (p.y_min_set && p.y_max_set) ImPlot::SetNextAxisLimits(ImAxis_Y1, p.y_min, p.y_max, ImPlotCond_Always);
  else if (p.y_min_set || p.y_max_set) {
    double minimum = INFINITY, maximum = -INFINITY;
    for (auto &curve : p.curves) if (curve.visible) if (auto data = channel(curve.name)) {
      for (auto &point : transform(*data, curve.scale, curve.offset, curve.derivative, curve.dt)) if (point.time >= origin() + x_min_ && point.time <= origin() + x_max_) {
        double value = point.value; minimum = std::min(minimum, value); maximum = std::max(maximum, value);
      }
    }
    if (!std::isfinite(minimum)) { minimum = 0; maximum = 1; }
    double margin = std::max(.01, (maximum - minimum) * .05);
    minimum = p.y_min_set ? p.y_min : minimum - margin; maximum = p.y_max_set ? p.y_max : maximum + margin;
    if (maximum <= minimum) { if (p.y_max_set) minimum = maximum - 1; else maximum = minimum + 1; }
    ImPlot::SetNextAxisLimits(ImAxis_Y1, minimum, maximum, ImPlotCond_Always);
  } else ImPlot::SetNextAxisToFit(ImAxis_Y1);
  if (!ImPlot::BeginPlot("##plot", size)) return;
  ImPlot::SetupAxes("Time (s)", nullptr);
  for (auto &curve : p.curves) {
    if (!curve.visible) continue;
    if (!std::isfinite(curve.scale) || !std::isfinite(curve.offset) || !std::isfinite(curve.dt) || curve.dt < 0) { error_ = "Curve transforms must be finite, with a nonnegative dt"; continue; }
    auto source = channel(curve.name);
    if (!source) { ImPlot::PlotDummy((curve.name + " (missing)").c_str()); continue; }
    std::string cache_key = curve.name + ":" + doubleToString(curve.scale) + ":" + doubleToString(curve.offset) + ":" + std::to_string(curve.derivative) + ":" + doubleToString(curve.dt);
    auto &cache = plot_cache_[cache_key];
    uint64_t revision = can->analysis_data.revision + can_revision_ + can_result_revision_;
    if (cache.revision != revision || cache.count != source->samples().size() || (!source->samples().empty() &&
        (cache.last_time != source->samples().back().time || cache.last_value != source->samples().back().value))) {
      cache.view_valid = false;
      cache.points = transform(*source, curve.scale, curve.offset, curve.derivative, curve.dt);
      cache.revision = revision; cache.count = source->samples().size();
      if (!source->samples().empty()) { cache.last_time = source->samples().back().time; cache.last_value = source->samples().back().value; }
    }
    const auto &values = cache.points;
    if (!analysis_launch.test_state.empty()) {
      J::object info{{"count", int(values.size())}};
      if (!values.empty()) { info["first"] = values.front().value; info["last"] = values.back().value; }
      test_plots_[curve.name] = info;
    }
    auto &x = cache.x; auto &y = cache.y;
    if (!cache.view_valid || cache.view_min != x_min_ || cache.view_max != x_max_ || cache.view_width != int(size.x)) {
      x.clear(); y.clear();
      cache.view_valid = true; cache.view_min = x_min_; cache.view_max = x_max_; cache.view_width = int(size.x);
      auto begin = std::lower_bound(values.begin(), values.end(), origin() + x_min_, [](auto &point, double t) { return point.time < t; });
      auto end = std::upper_bound(begin, values.end(), origin() + x_max_, [](double t, auto &point) { return t < point.time; });
      if (begin != values.begin()) --begin;
      if (end != values.end()) ++end;
      size_t count = std::distance(begin, end), bucket = std::max<size_t>(1, count / std::max(1, int(size.x * 2)));
      // Keep extrema in temporal order, so narrow spikes survive display decimation.
      auto append = [&](auto point) { x.push_back(point->time - origin()); y.push_back(point->value); };
      for (auto first = begin; first != end;) {
        auto last = first + std::min<size_t>(bucket, std::distance(first, end));
        auto [minimum, maximum] = std::minmax_element(first, last, [](auto &a, auto &b) { return a.value < b.value; });
        append(first);
        if (bucket == 1) { first = last; continue; }
        if (minimum < maximum) { append(minimum); append(maximum); } else { append(maximum); append(minimum); }
        append(std::prev(last)); first = last;
      }
    }
    unsigned color = 0x36a9e1; sscanf(curve.color.c_str(), "#%x", &color);
    ImPlotSpec spec; spec.LineColor = analysisCurveColor(color); spec.LineWeight = 1.8f;
    const char *label = curve.label.empty() ? curve.name.c_str() : curve.label.c_str();
    if (p.style == 1) ImPlot::PlotStairs(label, x.data(), y.data(), x.size(), spec);
    else if (p.style == 2) ImPlot::PlotScatter(label, x.data(), y.data(), x.size(), spec);
    else ImPlot::PlotLine(label, x.data(), y.data(), x.size(), spec);
  }
  if (!analysis_launch.test_state.empty()) {
    auto pos = ImPlot::GetPlotPos(), extent = ImPlot::GetPlotSize();
    test_items_["Plot canvas"] = J::array{J::array{pos.x, pos.y, pos.x + extent.x, pos.y + extent.y}};
  }
  double tracker = can->currentSec();
  if (ImPlot::DragLineX(987, &tracker, ImVec4(1, .5f, .2f, 1))) { can->pause(true); can->seekTo(tracker); }
  if (ImPlot::IsPlotHovered()) {
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && ImGui::GetIO().KeyCtrl) { can->pause(true); can->seekTo(ImPlot::GetPlotMousePos().x); }
    auto limits = ImPlot::GetPlotLimits();
    if (limits.X.Max > limits.X.Min) { x_min_ = limits.X.Min; x_max_ = limits.X.Max; }
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Right) || ImGui::IsMouseReleased(ImGuiMouseButton_Middle) || ImGui::GetIO().MouseWheel != 0) {
      layout_.range_set = true; layout_.x_min = x_min_; layout_.x_max = x_max_; checkpoint();
    }
    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) range_initialized_ = false;
  }
  if (ImPlot::BeginDragDropTargetPlot()) {
    if (ImGui::AcceptDragDropPayload("CABANA_ANALYSIS")) addSelected(p);
    ImPlot::EndDragDropTarget();
  }
  ImPlot::EndPlot();
}

void AnalysisWorkspace::map(ImVec2 size) {
  const Channel *lat = channel("/gpsLocationExternal/latitude"), *lon = channel("/gpsLocationExternal/longitude");
  if (!lat || !lon) { lat = channel("/gpsLocation/latitude"); lon = channel("/gpsLocation/longitude"); }
  if (!lat || !lon) { ImGui::TextUnformatted("No GPS samples in loaded data"); return; }
  std::vector<double> xs, ys, times;
  for (auto &s : lat->samples()) {
    auto longitude = lon->at(s.time);
    if (longitude && std::abs(*longitude) <= 180 && std::abs(s.value) <= 90) { xs.push_back(*longitude); ys.push_back(s.value); times.push_back(s.time); }
  }
  checkBox("Follow position", &map_follow_); ImGui::SameLine(); checkBox("Streets", &map_streets_);
  ImGui::SameLine(); bool fit = button("Fit route");
  if (map_request_.valid() && map_request_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
    try {
      auto result = map_request_.get(); map_roads_.clear();
      for (auto &road : result["roads"].array_items()) {
        std::vector<Sample> points; for (auto &point : road.array_items()) points.push_back({point[0].number_value(), point[1].number_value()});
        map_roads_.push_back(std::move(points));
      }
      map_error_.clear();
    } catch (const std::exception &e) { map_error_ = e.what(); }
  }
  if (!map_error_.empty()) ImGui::TextWrapped("%s", map_error_.c_str());
  if (map_streets_) ImGui::TextUnformatted("Map data (c) OpenStreetMap contributors (ODbL)");
  if (fit) ImPlot::SetNextAxesToFit();
  if (!xs.empty()) {
    auto [xmin, xmax] = std::minmax_element(xs.begin(), xs.end()); auto [ymin, ymax] = std::minmax_element(ys.begin(), ys.end());
    ImPlot::SetNextAxesLimits(*xmin - .0001, *xmax + .0001, *ymin - .0001, *ymax + .0001, ImPlotCond_Once);
  }
  if (map_follow_) {
    auto x = lon->at(origin() + can->currentSec()), y = lat->at(origin() + can->currentSec());
    if (x && y) ImPlot::SetNextAxesLimits(*x - .005, *x + .005, *y - .005, *y + .005, ImPlotCond_Always);
  }
  size.y = std::max(40.f, size.y - (map_streets_ ? 65 : 35) - (map_error_.empty() ? 0 : 30));
  if (ImPlot::BeginPlot("GPS map", size, ImPlotFlags_Equal)) {
    ImPlot::SetupAxes("Longitude", "Latitude");
    if (map_streets_) {
      auto limits = ImPlot::GetPlotLimits();
      J::array bounds{std::floor(limits.Y.Min * 100) / 100, std::floor(limits.X.Min * 100) / 100,
                     std::ceil(limits.Y.Max * 100) / 100, std::ceil(limits.X.Max * 100) / 100};
      std::string key = J(bounds).dump();
      if (!map_request_.valid() && key != map_key_ && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        map_key_ = key;
        J request = J::object{{"bounds", bounds}, {"cache", (utils::configPath() / "cabana-map-cache").string()}};
        std::string script = (executableDir() / "analysis/map_data.py").string();
        map_request_ = std::async(std::launch::async, [script, request]() { return cabana::analysis::pythonTask(script, request); });
      }
      for (size_t i = 0; i < map_roads_.size(); ++i) {
        auto &road = map_roads_[i]; if (road.empty()) continue;
        ImPlotSpec spec; spec.LineColor = ImVec4(.65f, .65f, .65f, 1); spec.Stride = sizeof(Sample); spec.Flags = ImPlotItemFlags_NoLegend;
        ImPlot::PlotLine(("##street" + std::to_string(i)).c_str(), &road.front().time, &road.front().value, road.size(), spec);
      }
    }
    ImPlotSpec route_spec; route_spec.LineColor = analysisCurveColor(0x57a9e3); route_spec.LineWeight = 2.f;
    ImPlot::PlotLine("Route", xs.data(), ys.data(), xs.size(), route_spec);
    auto longitude = lon->at(origin() + can->currentSec()), latitude = lat->at(origin() + can->currentSec());
    ImPlotSpec position_spec; position_spec.MarkerFillColor = analysisCurveColor(0xda6f25); position_spec.LineColor = position_spec.MarkerFillColor; position_spec.MarkerLineColor = position_spec.MarkerFillColor; position_spec.MarkerSize = 5.f;
    if (longitude && latitude) ImPlot::PlotScatter("Position", &*longitude, &*latitude, 1, position_spec);
    if (ImPlot::IsPlotHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !times.empty()) {
      auto mouse = ImPlot::GetPlotMousePos();
      size_t best = 0; double distance = INFINITY;
      for (size_t i = 0; i < times.size(); ++i) {
        double d = std::hypot(xs[i] - mouse.x, ys[i] - mouse.y);
        if (d < distance) { best = i; distance = d; }
      }
      can->pause(true); can->seekTo(times[best] - origin());
    }
    if (!analysis_launch.test_state.empty()) {
      auto pos = ImPlot::GetPlotPos(), extent = ImPlot::GetPlotSize();
      test_items_["GPS canvas"] = J::array{J::array{pos.x, pos.y, pos.x + extent.x, pos.y + extent.y}};
    }
    ImPlot::EndPlot();
  }
}
void AnalysisWorkspace::logs(ImVec2 size) {
  textInput("Search logs", &log_filter_); ImGui::SameLine(); textInput("Source", &source_filter_);
  ImGui::SetNextItemWidth(120); ImGui::Combo("Level", &log_level_, "All\0Debug+\0Info+\0Warning+\0Error+\0Critical\0");
  ImGui::SameLine(); ImGui::SetNextItemWidth(130); ImGui::Combo("Time", &log_time_, "Route\0Boot\0Wall clock\0");
  ImGui::SameLine(); if (button("Levels")) ImGui::OpenPopup("log_levels");
  if (ImGui::BeginPopup("log_levels")) {
    const char *names[] = {"Other", "Debug", "Info", "Warning", "Error", "Critical"};
    for (int i = 0; i < 6; ++i) { bool enabled = log_levels_ & (1U << i); if (checkBox(names[i], &enabled)) log_levels_ ^= (1U << i); }
    ImGui::EndPopup();
  }
  ImGui::SameLine(); if (button("Sources")) ImGui::OpenPopup("log_sources");
  if (ImGui::BeginPopup("log_sources")) {
    if (button("All sources")) log_sources_.clear();
    std::set<std::string> sources; for (auto &line : can->analysis_data.logs) sources.insert(line.source);
    for (auto &source : sources) { bool selected = log_sources_.count(source); if (checkBox(source.c_str(), &selected)) { if (selected) log_sources_.insert(source); else log_sources_.erase(source); } }
    ImGui::EndPopup();
  }
  if (ImGui::BeginTable("log_table", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable, ImVec2(size.x, std::max(40.f, size.y - 90)))) {
    ImGui::TableSetupColumn("Time"); ImGui::TableSetupColumn("Level"); ImGui::TableSetupColumn("Source"); ImGui::TableSetupColumn("Message"); ImGui::TableHeadersRow();
    std::vector<const LogLine *> rows;
    for (auto &line : can->analysis_data.logs) {
      if (!(log_levels_ & (1U << std::clamp(line.level / 10, 0, 5))) || (!log_sources_.empty() && !log_sources_.count(line.source)) || line.level < log_level_ * 10 || (!log_filter_.empty() && (line.message + line.context).find(log_filter_) == std::string::npos) ||
          (!source_filter_.empty() && line.source.find(source_filter_) == std::string::npos)) continue;
      rows.push_back(&line);
    }
    ImGuiListClipper clip; clip.Begin(rows.size());
    while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
      const auto &line = *rows[i];
      ImGui::PushID(i); ImGui::TableNextRow(); ImGui::TableNextColumn();
      char time[64]; snprintf(time, sizeof(time), "%.3f", log_time_ == 2 ? line.wall : line.time - (log_time_ == 0 ? origin() : 0));
      if (ImGui::Selectable(time, false, ImGuiSelectableFlags_None)) { can->pause(true); can->seekTo(line.time - origin()); }
      record("Log row " + std::to_string(i));
      if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", line.message.c_str(), line.context.c_str());
      std::string cells[] = {std::to_string(line.level), line.source, line.message};
      for (int column = 0; column < 3; ++column) {
        ImGui::TableNextColumn(); ImGui::PushID(column);
        if (ImGui::Selectable(cells[column].c_str(), false)) { can->pause(true); can->seekTo(line.time - origin()); }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", line.message.c_str(), line.context.c_str());
        ImGui::PopID();
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
}
void AnalysisWorkspace::media(Pane &p, ImVec2 size, const std::string &id) {
  active_cameras_.insert(id + p.camera);
  if (p.kind == "thumbnail") {
    auto &frames = can->analysis_data.thumbnails;
    auto it = std::upper_bound(frames.begin(), frames.end(), origin() + can->currentSec(), [](double t, auto &f) { return t < f.time; });
    if (it == frames.begin()) { ImGui::TextUnformatted("No thumbnail at this time"); return; }
    --it; uint64_t key = uint64_t(std::llround(it->time * 1e9));
    if (thumbnail_.key != key) {
      RgbImage image;
      if (decodeJpeg(it->jpeg.data(), it->jpeg.size(), &image)) { thumbnail_.upload(image); thumbnail_.key = key; }
    }
    if (thumbnail_.id) {
      const ImVec2 start = ImGui::GetCursorScreenPos();
      const ImRect bounds(start, ImVec2(start.x + size.x, start.y + size.y));
      const VideoPlacement placement = videoPlacement(bounds, float(thumbnail_.width) / thumbnail_.height, settings.crop_video);
      ImDrawList *draw = ImGui::GetWindowDrawList();
      draw->AddRectFilled(bounds.Min, bounds.Max, IM_COL32(12, 14, 15, 255), 4.f);
      draw->AddImageRounded(thumbnail_.ref(), placement.min, placement.max, placement.uv0, placement.uv1, IM_COL32_WHITE, ImGui::GetStyle().ChildRounding);
      ImGui::Dummy(size);
    }
    return;
  }
  if (!can->liveStreaming()) {
    std::string service = p.camera == "driver" || p.camera == "cabin" ? "cabinEncodeIdx" : p.camera == "wide_road" ? "wideRoadEncodeIdx" : p.camera == "qroad" ? "qNarrowRoadEncodeIdx" : "narrowRoadEncodeIdx";
    const auto *indices = channel("/" + service + "/segmentId");
    auto frame = indices ? indices->at(origin() + can->currentSec()) : std::nullopt;
    std::string file;
    if (auto replay = dynamic_cast<ReplayStream *>(can)) {
      int segment = int(can->currentSec() / 60);
      if (auto segments = channel("/" + service + "/segmentNum")) if (auto number = segments->at(origin() + can->currentSec())) segment = *number;
      auto &files = replay->getReplay()->route().segments(); auto found = files.find(segment);
      if (found != files.end()) {
        auto &entry = found->second;
        file = p.camera == "driver" || p.camera == "cabin" ? entry.cabin_cam : p.camera == "wide_road" ? entry.wide_road_cam : p.camera == "qroad" ? entry.qcamera : entry.narrow_road_cam;
      }
    } else if (dynamic_cast<LogFileStream *>(can)) {
      const char *name = p.camera == "driver" || p.camera == "cabin" ? "dcamera.hevc" : p.camera == "wide_road" ? "ecamera.hevc" : p.camera == "qroad" ? "qcamera.ts" : "fcamera.hevc";
      auto path = std::filesystem::path(can->routeName()).parent_path() / name;
      if (std::filesystem::exists(path)) file = path.string();
    }
    auto &camera = file_cameras_[id + p.camera]; if (!camera) camera = std::make_unique<AnalysisCamera>();
    camera->draw(file, frame ? int(*frame) : -1, size);
    test_plots_[p.camera + " camera"] = J::object{{"frame", camera->displayedFrame()}};
    return;
  }
  auto &camera = cameras_[id + p.camera];
  if (!camera) {
    VisionStreamType type = p.camera == "driver" || p.camera == "cabin" ? VISION_STREAM_CABIN :
                            p.camera == "wide_road" ? VISION_STREAM_WIDE_ROAD : VISION_STREAM_NARROW_ROAD;
    camera = std::make_unique<StreamCameraView>("camerad", type);
  }
  camera->draw(size);
}
void AnalysisWorkspace::pane(Pane &p, ImVec2 size, const std::string &id) {
  size.x = std::max(30.f, size.x); size.y = std::max(30.f, size.y);
  ImGui::PushID(id.c_str());
  if (!p.children.empty()) {
    bool horizontal = p.split == "horizontal";
    double total = std::accumulate(p.sizes.begin(), p.sizes.end(), 0.0);
    float length = std::max(20.f, (horizontal ? size.x : size.y) - 6 * (p.children.size() - 1));
    ImVec2 start = ImGui::GetCursorPos(); float offset = 0;
    for (size_t i = 0; i < p.children.size(); ++i) {
      ImVec2 part = size;
      float extent = length * p.sizes[i] / total;
      if (horizontal) part.x = extent; else part.y = extent;
      ImGui::SetCursorPos(ImVec2(start.x + (horizontal ? offset : 0), start.y + (horizontal ? 0 : offset)));
      pane(p.children[i], part, id + "/" + std::to_string(i)); offset += extent;
      if (i + 1 < p.children.size()) {
        ImGui::SetCursorPos(ImVec2(start.x + (horizontal ? offset : 0), start.y + (horizontal ? 0 : offset)));
        ImGui::PushID(int(i)); ImGui::InvisibleButton("splitter", horizontal ? ImVec2(6, size.y) : ImVec2(size.x, 6));
        if (ImGui::IsItemActive()) {
          double delta = (horizontal ? ImGui::GetIO().MouseDelta.x : ImGui::GetIO().MouseDelta.y) * total / length;
          delta = std::clamp(delta, -p.sizes[i] + 0.05, p.sizes[i + 1] - 0.05);
          p.sizes[i] += delta; p.sizes[i + 1] -= delta;
        }
        if (ImGui::IsItemDeactivatedAfterEdit()) checkpoint();
        ImGui::PopID(); offset += 6;
      }
    }
    bool removed = false;
    for (int i = int(p.children.size()) - 1; i >= 0; --i) if (p.children[i].kind == "closed") {
      p.children.erase(p.children.begin() + i); p.sizes.erase(p.sizes.begin() + i); removed = true;
    }
    if (p.children.size() == 1) { Pane remaining = std::move(p.children.front()); p = std::move(remaining); }
    else if (p.children.empty()) p = {};
    if (removed) checkpoint();
    ImGui::SetCursorPos(start); ImGui::Dummy(size); ImGui::PopID(); return;
  }
  ImGui::BeginChild("pane", size, ImGuiChildFlags_Borders);
  bool split_h = false, split_v = false, close_pane = false;
  ImGui::AlignTextToFramePadding();
  sectionTitle(p.title.empty() || p.title == "..." ? (p.kind == "plot" ? "Time series" : p.kind.c_str()) : p.title.c_str());
  ImGui::SameLine(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowContentRegionMax().x - ImGui::CalcTextSize("Options").x - ImGui::GetStyle().FramePadding.x * 2));
  if (button("Options")) ImGui::OpenPopup("pane_menu");
  ImGui::Separator();
  if (ImGui::BeginPopup("pane_menu")) {
    textInput("Title", &p.title);
    if (menuItem("Add selected signals")) addSelected(p);
    close_pane = menuItem("Close pane");
    split_h = menuItem("Split left / right"); split_v = menuItem("Split top / bottom");
    for (const char *kind : {"plot", "map", "logs", "thumbnail", "camera"}) if (ImGui::MenuItem(kind, nullptr, p.kind == kind)) { p.kind = kind; p.title = kind; checkpoint(); }
    if (p.kind == "camera") for (const char *view : {"road", "wide_road", "driver", "qroad"}) if (ImGui::MenuItem(view, nullptr, p.camera == view)) { p.camera = view; checkpoint(); }
    if (ImGui::MenuItem("Remove all curves")) { p.curves.clear(); checkpoint(); }
    checkBox("Y minimum", &p.y_min_set); if (p.y_min_set) ImGui::InputDouble("Minimum", &p.y_min);
    checkBox("Y maximum", &p.y_max_set); if (p.y_max_set) ImGui::InputDouble("Maximum", &p.y_max);
    ImGui::Combo("Style", &p.style, "Line\0Step\0Scatter\0");
    for (size_t i = 0; i < p.curves.size(); ++i) {
      auto &curve = p.curves[i]; ImGui::PushID(int(i));
      bool expanded = ImGui::TreeNode(curve.name.c_str()); record("Curve " + curve.name);
      if (expanded) {
        checkBox("Visible", &curve.visible); record("Curve visible"); textInput("Label", &curve.label); textInput("Color", &curve.color);
        checkBox("First derivative", &curve.derivative); record("First derivative"); ImGui::InputDouble("dt (0 = actual)", &curve.dt);
        ImGui::InputDouble("Scale", &curve.scale); record("Scale"); ImGui::InputDouble("Offset", &curve.offset); record("Offset");
        bool remove = button("Remove curve");
        ImGui::TreePop(); if (remove) { p.curves.erase(p.curves.begin() + i); checkpoint(); ImGui::PopID(); break; }
      }
      ImGui::PopID();
    }
    if (button("Apply")) { checkpoint(); ImGui::CloseCurrentPopup(); }
    ImGui::EndPopup();
  }
  ImVec2 remaining = ImGui::GetContentRegionAvail(); remaining.y = std::max(30.f, remaining.y);
  if (p.kind == "map") map(remaining);
  else if (p.kind == "logs") logs(remaining);
  else if (p.kind == "thumbnail" || p.kind == "camera") {
    // Match the plot frame, including while a feed is loading or has no data.
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, ImGui::GetStyle().FrameRounding);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    if (ImGui::BeginChild("media_frame", remaining, ImGuiChildFlags_None,
                          ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
      const ImVec2 start = ImGui::GetCursorScreenPos();
      const ImVec2 content = ImGui::GetContentRegionAvail();
      if (content.x > 0 && content.y > 0) {
        const ImVec2 end(start.x + content.x, start.y + content.y);
        ImDrawList *draw = ImGui::GetWindowDrawList();
        const float rounding = ImGui::GetStyle().ChildRounding;
        draw->AddRectFilled(start, end, ImGui::GetColorU32(ImGuiCol_ChildBg), rounding);
        media(p, content, id);
        // Draw last, on the image bounds. A child-window border uses different
        // insets and clipping, leaving a square outline over the rounded video.
        draw->AddRect(start, end, ImGui::GetColorU32(ImGuiCol_Border), rounding);
      }
    }
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
  }
  else plot(p, remaining);
  ImGui::EndChild();
  if (close_pane) { p = {}; if (id.find('/') != std::string::npos) p.kind = "closed"; checkpoint(); }
  if ((split_h || split_v) && std::count(id.begin(), id.end(), '/') < 24) { Pane old = p; p = {}; p.split = split_h ? "horizontal" : "vertical"; p.children = {old, Pane{}}; p.sizes = {1, 1}; checkpoint(); }
  ImGui::PopID();
}

void AnalysisWorkspace::draw() {
  test_items_.clear(); test_plots_.clear();
  active_cameras_.clear();
  pollEvaluation();
  if (visible) { refreshCan(); pollCan(); refreshFormulas(); }
  if (ImGui::GetTime() >= next_autosave_) {
    auto snapshot = layout_.json().dump();
    if (snapshot != autosave_snapshot_) {
      auto previous_path = path_; auto previous_error = error_;
      save((utils::configPath() / "cabana-analysis.json").string()); path_ = previous_path;
      if (!previous_error.empty()) error_ = previous_error;
      autosave_snapshot_ = snapshot;
    }
    next_autosave_ = ImGui::GetTime() + 1;
  }
  if (!visible) { cameras_.clear(); file_cameras_.clear(); return; }
  if (plot_cache_.size() > 512) plot_cache_.clear();
  if (!range_initialized_ && can->maxSeconds() > 0) { x_min_ = can->minSeconds(); x_max_ = std::max(x_min_ + 1, can->maxSeconds()); range_initialized_ = true; }
  AnalysisStyle analysis_style;
  ImGui::PushStyleColor(ImGuiCol_ChildBg, isDarkTheme() ? colorRgb(29, 34, 37) : colorRgb(238, 239, 240));
  bool workspace_open = ImGui::BeginChild("AnalysisWorkspace", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding);
  ImGui::PopStyleColor();
  if (workspace_open) {
    toolbar();
    ImGui::Separator();
    if (!error_.empty()) ImGui::TextWrapped("%s", error_.c_str());
    if (fps_) ImGui::Text("%.1f FPS", ImGui::GetIO().Framerate);
    ImGui::BeginChild("browser", ImVec2(310, 0), ImGuiChildFlags_ResizeX | ImGuiChildFlags_Borders); browser(); ImGui::EndChild();
    ImGui::SameLine(); ImGui::BeginChild("workspace", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground);
    if (ImGui::BeginTabBar("analysis_tabs")) {
      int close = -1, duplicate = -1, move_tab = -1, move_direction = 0, requested_tab = select_tab_ ? layout_.active : -1;
      select_tab_ = false;
      for (int i = 0; i < int(layout_.tabs.size()); ++i) {
        auto &tab = layout_.tabs[i]; bool open = true;
        ImGui::PushID(i);
        if (ImGui::BeginTabItem((tab.name + "###tab" + std::to_string(i)).c_str(), &open, i == requested_tab ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None)) {
          record("Tab " + tab.name);
          layout_.active = i;
          if (ImGui::BeginPopupContextItem("tab_menu")) {
            textInput("Name", &tab.name);
            if (ImGui::MenuItem("Move tab left", nullptr, false, i > 0)) { move_tab = i; move_direction = -1; } record("Move tab left");
            if (ImGui::MenuItem("Move tab right", nullptr, false, i + 1 < int(layout_.tabs.size()))) { move_tab = i; move_direction = 1; }
            if (ImGui::MenuItem("Duplicate tab")) duplicate = i;
            if (ImGui::MenuItem("Close tab")) close = i;
            ImGui::EndPopup();
          }
          pane(tab.root, ImGui::GetContentRegionAvail(), "tab" + std::to_string(i)); ImGui::EndTabItem();
        }
        record("Tab " + tab.name);
        if (!open) close = i;
        ImGui::PopID();
      }
      bool add = ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing); record("New tab");
      ImGui::EndTabBar();
      if (move_tab >= 0) { std::swap(layout_.tabs[move_tab], layout_.tabs[move_tab + move_direction]); layout_.active = move_tab + move_direction; select_tab_ = true; checkpoint(); }
      if (duplicate >= 0 && layout_.tabs.size() < 64) { Tab copy = layout_.tabs[duplicate]; copy.name += " copy"; layout_.tabs.push_back(copy); checkpoint(); }
      if (close >= 0 && layout_.tabs.size() > 1) { layout_.tabs.erase(layout_.tabs.begin() + close); layout_.active = std::min(layout_.active, int(layout_.tabs.size()) - 1); checkpoint(); }
      if (add && layout_.tabs.size() < 64) { layout_.tabs.push_back(Tab{"Tab " + std::to_string(layout_.tabs.size() + 1), {}}); checkpoint(); }
    }
    ImGui::EndChild();
  }
  ImGui::EndChild();
  for (auto it = cameras_.begin(); it != cameras_.end();) { if (!active_cameras_.count(it->first)) it = cameras_.erase(it); else ++it; }
  for (auto it = file_cameras_.begin(); it != file_cameras_.end();) { if (!active_cameras_.count(it->first)) it = file_cameras_.erase(it); else ++it; }
  editor();
  if (layout_editor_) {
    ImGui::SetNextWindowSize(ImVec2(800, 650), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Layout JSON", &layout_editor_)) {
      inputTextMultiline("##layout_source", &layout_source_, ImVec2(-1, -65));
      if (button("Apply layout")) {
        try {
          std::string error; auto parsed = J::parse(layout_source_, error);
          if (!error.empty()) throw std::runtime_error(error);
          auto next = Layout::parse(parsed);
          layout_ = std::move(next); select_tab_ = true; range_initialized_ = layout_.range_set;
          if (layout_.range_set) { x_min_ = layout_.x_min; x_max_ = layout_.x_max; }
          custom_channels_.clear(); browser_dirty_ = true; formula_signature_.clear(); checkpoint(); error_.clear();
        } catch (const std::exception &e) { error_ = e.what(); }
      }
      ImGui::SameLine(); if (button("Reload source")) layout_source_ = layout_.json().dump();
      ImGui::SameLine(); if (button("Save layout")) shortcut('S', false);
      if (!error_.empty()) ImGui::TextWrapped("%s", error_.c_str());
    }
    ImGui::End();
  }
}

void AnalysisWorkspace::evaluate(bool apply) {
  if (evaluation_.valid()) return;
  try {
    if (formula_.name.empty()) throw std::runtime_error("Give the custom series a name");
    formula_.additional.clear(); std::istringstream lines(extra_sources_); std::string line;
    while (std::getline(lines, line)) if (!line.empty()) formula_.additional.push_back(line);
    auto channels = formulaInputs({formula_});
    Layout request; request.formulas = {formula_};
    auto spec = request.json()["formulas"][0];
    evaluating_formula_ = formula_; apply_evaluation_ = apply; batch_evaluation_ = false; error_.clear();
    std::string script = (executableDir() / "analysis/evaluate.py").string();
    evaluation_ = std::async(std::launch::async, [script, channels = std::move(channels), spec, start = origin()]() {
      return cabana::analysis::pythonTask(script, J::object{{"channels", serializeInputs(channels, start)}, {"formula", spec}});
    });
  } catch (const std::exception &e) { error_ = e.what(); }
}
void AnalysisWorkspace::pollEvaluation() {
  if (!evaluation_.valid() || evaluation_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
  try {
    auto result = evaluation_.get(); plot_cache_.clear();
    if (batch_evaluation_) {
      if (layout_.json()["formulas"].dump() != formula_signature_) return;
      custom_channels_.clear(); browser_dirty_ = true; formula_errors_.clear();
      for (auto &[name, samples] : result["results"].object_items()) {
        auto &destination = custom_channels_[name];
        for (auto &point : samples.array_items()) destination.editSamples().push_back({origin() + point[0].number_value(), point[1].number_value()});
      }
      for (auto &[name, error] : result["errors"].object_items()) formula_errors_[name] = error.string_value();
      return;
    }
    preview_.clear();
    for (auto &point : result["samples"].array_items()) preview_.push_back({point[0].number_value(), point[1].number_value()});
    if (apply_evaluation_) {
      auto &destination = custom_channels_[evaluating_formula_.name]; destination.editSamples() = preview_;
      for (auto &point : destination.editSamples()) point.time += origin();
      auto found = std::find_if(layout_.formulas.begin(), layout_.formulas.end(), [&](auto &f) { return f.name == evaluating_formula_.name; });
      if (found == layout_.formulas.end()) layout_.formulas.push_back(evaluating_formula_); else *found = evaluating_formula_;
      selected_ = evaluating_formula_.name; selection_ = {selected_}; checkpoint();
    }
  } catch (const std::exception &e) { error_ = e.what(); }
}
void AnalysisWorkspace::editor() {
  pollEvaluation();
  if (!formula_open_) return;
  ImGui::SetNextWindowSize(ImVec2(820, 720), ImGuiCond_FirstUseEver);
  if (ImGui::Begin("Custom Python series", &formula_open_)) {
    if (ImGui::BeginCombo("Saved series", formula_.name.c_str())) {
      for (auto &f : layout_.formulas) if (ImGui::Selectable(f.name.c_str())) {
        formula_ = f; extra_sources_.clear(); for (auto &s : f.additional) extra_sources_ += s + '\n';
      }
      ImGui::EndCombo();
    }
    ImGui::BeginDisabled(evaluation_.valid());
    if (button("New series")) { formula_ = {}; extra_sources_.clear(); preview_.clear(); }
    ImGui::SameLine();
    if (button("Delete series")) {
      layout_.formulas.erase(std::remove_if(layout_.formulas.begin(), layout_.formulas.end(), [this](const auto &f) { return f.name == formula_.name; }), layout_.formulas.end());
      custom_channels_.erase(formula_.name); formula_errors_.erase(formula_.name); preview_.clear(); plot_cache_.clear(); checkpoint();
    }
    ImGui::EndDisabled();
    textInput("Name", &formula_.name); textInput("Input series", &formula_.source);
    ImGui::SameLine(); if (button("Use selected")) formula_.source = selected_;
    ImGui::TextUnformatted("Additional sources (one path per line; v1, v2, ...)");
    inputTextMultiline("##extra", &extra_sources_, ImVec2(-1, 60));
    ImGui::TextUnformatted("Globals (Python)"); inputTextMultiline("##globals", &formula_.globals, ImVec2(-1, 80));
    ImGui::TextUnformatted("Expression or function body"); inputTextMultiline("##formula", &formula_.code, ImVec2(-1, 100)); record("Formula code"); test_texts_["Formula code"] = formula_.code;
    ImGui::TextWrapped("NumPy: np; input: time, value; extra inputs: v1, v2; t(path), v(path) access arrays. Return values or (times, values). Additional inputs use the last value at or before each input timestamp.");
    if (button("Example: km/h")) formula_.code = "return value * 3.6";
    ImGui::SameLine(); if (button("Example: gradient")) formula_.code = "return np.gradient(value, time)";
    ImGui::BeginDisabled(evaluation_.valid());
    if (button("Preview result")) evaluate(false);
    ImGui::SameLine(); if (button("Apply series")) evaluate(true);
    ImGui::SameLine(); if (button("Close editor")) formula_open_ = false;
    ImGui::EndDisabled();
    if (evaluation_.valid()) ImGui::TextUnformatted("Evaluating...");
    if (!error_.empty()) ImGui::TextWrapped("%s", error_.c_str());
    if (!preview_.empty() && ImPlot::BeginPlot("Preview", ImVec2(-1, 150))) {
      ImPlotSpec spec; spec.Stride = sizeof(Sample); ImPlot::PlotLine("Result", &preview_.front().time, &preview_.front().value, preview_.size(), spec); ImPlot::EndPlot();
    }
  }
  ImGui::End();
}

std::map<std::string, Channel> AnalysisWorkspace::formulaInputs(const std::vector<Formula> &formulas) const {
  std::set<std::string> names;
  for (auto &formula : formulas) {
    if (!formula.source.empty()) names.insert(formula.source);
    names.insert(formula.additional.begin(), formula.additional.end());
    for (const std::map<std::string, Channel> *collection : {static_cast<const std::map<std::string, Channel> *>(&can->analysis_data.channels), static_cast<const std::map<std::string, Channel> *>(&can_channels_), &custom_channels_})
      for (auto &[name, _] : *collection) if (formula.code.find(name) != std::string::npos || formula.globals.find(name) != std::string::npos) names.insert(name);
  }
  std::map<std::string, Channel> result;
  for (const auto &name : names) if (auto data = channel(name)) result[name] = *data;
  return result;
}
void AnalysisWorkspace::refreshFormulas() {
  if (layout_.formulas.empty() || !can->analysis_data.revision || evaluation_.valid() || ImGui::GetTime() < next_formula_refresh_) return;
  auto formulas = layout_.json()["formulas"];
  auto signature = formulas.dump();
  uint64_t revision = can->analysis_data.revision + can_revision_ + can_result_revision_;
  if (signature == formula_signature_ && formulas_revision_ == revision) return;
  formula_signature_ = signature; formulas_revision_ = revision;
  next_formula_refresh_ = ImGui::GetTime() + 1;
  auto inputs = formulaInputs(layout_.formulas);
  for (auto &formula : layout_.formulas) inputs.erase(formula.name);  // cycles must not consume stale results
  std::string script = (executableDir() / "analysis/evaluate.py").string();
  batch_evaluation_ = true;
  evaluation_ = std::async(std::launch::async, [script, inputs = std::move(inputs), formulas, start = origin()]() {
    return cabana::analysis::pythonTask(script, J::object{{"channels", serializeInputs(inputs, start)}, {"formulas", formulas}});
  });
}

void AnalysisWorkspace::record(const std::string &label) {
  if (analysis_launch.test_state.empty() || !ImGui::IsItemVisible()) return;
  auto low = ImGui::GetItemRectMin(), high = ImGui::GetItemRectMax();
  auto entries = test_items_[label].array_items();
  entries.push_back(J::array{low.x, low.y, high.x, high.y}); test_items_[label] = entries;
}
bool AnalysisWorkspace::button(const char *label) { bool result = ImGui::Button(label); record(label); return result; }
bool AnalysisWorkspace::textInput(const char *label, std::string *value) { bool result = inputText(label, value); record(label); test_texts_[label] = *value; return result; }

void AnalysisWorkspace::shortcut(int key, bool shift) {
  if (key == 'F') focus_search_ = true;
  if (key == 'Z') undo(shift ? 1 : -1);
  if (key == 'N') { layout_ = {}; custom_channels_.clear(); browser_dirty_ = true; range_initialized_ = false; checkpoint(); }
  if (key == 'O') FileDialog::getOpenFileName("Load analysis layout", "", "", utils::guarded(alive_, [this](const std::string &path) { if (!path.empty()) load(path); }));
  if (key == 'S') {
    if (!shift && !path_.empty()) save(path_);
    else FileDialog::getSaveFileName("Save analysis layout", "analysis.json", ".json", utils::guarded(alive_, [this](const std::string &path) { if (!path.empty()) save(path); }));
  }
}

void AnalysisWorkspace::restore(const std::string &json) {
  std::string error;
  try {
    auto state = J::parse(json, error);
    if (!error.empty()) throw std::runtime_error(error);
    layout_ = Layout::parse(state["layout"]);
    select_tab_ = true;
    path_ = state["layout_path"].string_value();
    range_initialized_ = false; checkpoint();
  } catch (const std::exception &e) { error_ = e.what(); }
}

bool AnalysisWorkspace::menuItem(const char *label) { bool result = ImGui::MenuItem(label); record(label); return result; }
