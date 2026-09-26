#include "tools/cabana/ui/mainwin.h"

#include <filesystem>
#include <fstream>

#include "common/util.h"
#include "tools/cabana/settings.h"
#include "tools/cabana/streams/replaystream.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/ui/dialogs/messagebox.h"
#include "tools/cabana/ui/inistate.h"
#include "tools/cabana/ui/threadpool.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/workspace.h"

using json11::Json;

namespace {
// Also renames the source's panels in the ImGui ini, so they keep their docking.
Json remapSource(const Json &input, const std::string &from, const std::string &to) {
  auto document = cabana::remapWorkspaceSource(input, from, to).object_items();
  std::string ui = document["ui"].string_value();
  auto replace = [&](const std::string &a, const std::string &b) {
    for (size_t pos = 0; (pos = ui.find(a, pos)) != std::string::npos; pos += b.size()) ui.replace(pos, a.size(), b);
  };
  for (const char *kind : {"can", "logs", "inspector"}) {
    const auto old_name = std::string("###") + kind + "_" + from, new_name = std::string("###") + kind + "_" + to;
    replace(old_name + "]", new_name + "]");
    char old_tab[16], new_tab[16];  // dock nodes remember their selected tab by the window's tab id
    snprintf(old_tab, sizeof(old_tab), "0x%08X", ImHashStr("#TAB", 4, ImHashStr(old_name.c_str())));
    snprintf(new_tab, sizeof(new_tab), "0x%08X", ImHashStr("#TAB", 4, ImHashStr(new_name.c_str())));
    replace(old_tab, new_tab);
  }
  document["ui"] = ui;
  return document;
}

Json blankWorkspace(const std::string &name, const Json::array &sources = {}) {
  return Json::object{{"cabana_workspace", 2}, {"name", name}, {"ui", ""}, {"sources", sources}, {"widgets", Json::array{}},
                      {"timeline", Json::object{}}, {"charts", Json::object{{"cabana_layout", 4}, {"range", 60}, {"charts", Json::array{}}}}};
}

Json builtinWorkspace(const std::string &key, const std::string &name) {
  auto doc = blankWorkspace(name).object_items();
  doc["builtin"] = key;
  return doc;
}
}  // namespace

// An id no open source uses, and that neither `document` nor the active workspace refers to.
std::string MainWindow::newSourceId(const Json &document) {
  const auto used = [&](const std::string &id) {
    return sourceById(id) || document.dump().find('"' + id + '"') != std::string::npos ||
           (!workspaces_.empty() && workspaces_[active_workspace_].dump().find('"' + id + '"') != std::string::npos);
  };
  std::string id;
  do { id = "source" + std::to_string(next_source_id_++); } while (used(id));
  return id;
}

void MainWindow::initializeWorkspaces(bool use_default) {
  workspaces_ = {builtinWorkspace("default", "Default"), builtinWorkspace("live", "Live")};
  std::vector<std::filesystem::path> presets;
  std::error_code file_error;
  for (const auto &entry : std::filesystem::directory_iterator(executableDir() / "layouts", file_error))
    if (entry.path().extension() == ".json") presets.push_back(entry.path());
  std::sort(presets.begin(), presets.end());
  for (const auto &path : presets) workspaces_.push_back(builtinWorkspace("layout:" + path.filename().string(), path.stem().string()));
  std::string error;
  const auto library = Json::parse(settings.workspaces, error);
  const auto &saved = library["workspaces"].array_items();
  for (int i = 0; i < (int)saved.size(); ++i) {
    if (!cabana::validWorkspace(saved[i]) || cabana::isBuiltinWorkspace(saved[i])) continue;
    if (i == library["active"].int_value()) active_workspace_ = workspaces_.size();
    workspaces_.push_back(saved[i]);
  }
  const auto &active_builtin = library["active_builtin"];
  for (int i = 0; i < (int)workspaces_.size(); ++i)
    if (!active_builtin.string_value().empty() && workspaces_[i]["builtin"] == active_builtin) active_workspace_ = i;
  switchWorkspace(use_default ? 0 : active_workspace_, false);
}

void MainWindow::resetBuiltinWorkspace() {
  const auto key = workspaces_[active_workspace_]["builtin"].string_value();
  if (key.empty()) return;
  auto doc = builtinWorkspace(key, workspaces_[active_workspace_]["name"].string_value()).object_items();
  doc["builtin_initialized"] = true;
  doc["default"] = key == "default";
  if (key.rfind("layout:", 0) == 0) {
    std::string error;
    doc["charts"] = Json::parse(util::read_file((executableDir() / "layouts" / key.substr(7)).string()), error);
    if (!chart::parseLayout(doc["charts"].dump())) { MessageBox::warning("Workspace preset", "Unsupported preset."); return; }
  }
  // Built-ins keep every open source. Live selects the live connection, or a slot for one.
  Json::array slots;
  for (const auto &view : source_views_) slots.push_back(Json::object{{"id", view->stream->source_id}, {"label", view->stream->source_label}});
  std::string target = selected_source_;
  if (key == "live") {
    auto find = [&](auto match) {
      for (const auto &view : source_views_) if (match(view->stream.get())) return view->stream->source_id;
      return std::string();
    };
    target = find([](AbstractStream *s) { return s->liveStreaming() && !dynamic_cast<DummyStream *>(s); });
    if (target.empty()) target = find([](AbstractStream *s) { return dynamic_cast<DummyStream *>(s) && s->source_label == "Live source"; });
    if (target.empty()) slots.push_back(Json::object{{"id", target = newSourceId()}, {"label", "Live source"}});
  }
  doc["sources"] = slots;
  doc["timeline"] = Json::object{{"selected", target}};
  workspaces_[active_workspace_] = doc;
  applyWorkspace(doc);
  selectSource(target);
  if (key == "live") {
    auto &view = currentSource();
    view.messages_visible = view.logs_visible = view.inspector_visible = true;
    charts_widget_->newChart();
    reset_layout_ = true;
  } else {
    makeDefaultWidgets();
  }
}

void MainWindow::captureWorkspace() {
  if (!charts_widget_ || workspaces_.empty()) return;
  const auto previous = workspaces_[active_workspace_]["sources"].array_items();
  auto doc = workspaces_[active_workspace_].object_items();
  std::string error;
  doc["charts"] = Json::parse(charts_widget_->serializeLayout(), error);
  doc["ui"] = inistate::save();
  doc["timeline"] = timeline_.snapshot();
  doc["selected_source"] = selected_source_;
  doc["default"] = default_workspace_;
  doc["include_routes"] = include_routes_;
  doc["timeline_visible"] = playback_visible_;
  doc["timeline_expanded"] = playback_expanded_;
  doc["timeline_height"] = playback_height_;
  Json::array sources, widgets;
  for (auto &view : source_views_) {
    auto *stream = view->stream.get();
    Json::object source{{"id", stream->source_id}, {"label", stream->source_label}};
    if (auto *replay = dynamic_cast<ReplayStream *>(stream); replay && include_routes_) {
      source["route"] = replay->routeReference();
      if (!replay->dataDirectory().empty()) source["data_dir"] = replay->dataDirectory();
      Json::array dbcs;
      for (auto *file : stream->database()->nonEmptyDBCFiles()) {
        const auto buses = stream->database()->sources(file);
        if (!file->filename.empty()) dbcs.push_back(Json::object{{"file", file->filename}, {"buses", Json::array(buses.begin(), buses.end())}});
      }
      source["dbcs"] = dbcs;
    } else if (dynamic_cast<DummyStream *>(stream) && include_routes_) {
      // An unloaded slot keeps its saved references.
      for (const auto &saved : previous) if (saved["id"] == stream->source_id) {
        for (const char *key : {"route", "data_dir", "dbcs"}) if (!saved[key].is_null()) source[key] = saved[key];
      }
    }
    // Inspector tabs still waiting for their DBC keep the saved selection.
    if (auto pending = pending_workspace_inspectors_.find(stream->source_id); pending != pending_workspace_inspectors_.end()) {
      source["inspector"] = pending->second;
    } else if (auto *detail = view->inspector.getDetailWidget()) {
      auto [active, ids] = detail->serializeMessageIds();
      source["inspector"] = Json::object{{"active", active}, {"messages", Json::array(ids.begin(), ids.end())}};
    }
    sources.push_back(source);
    for (auto [kind, visible] : {std::pair{"can", view->messages_visible}, {"logs", view->logs_visible}, {"inspector", view->inspector_visible}}) {
      if (visible) widgets.push_back(Json::object{{"kind", kind}, {"source", stream->source_id}});
    }
  }
  for (const auto &camera : camera_panes_) if (camera.visible) {
    widgets.push_back(Json::object{{"kind", "camera"}, {"id", camera.id}, {"source", camera.source},
                                  {"camera", (int)camera.type}, {"crop", camera.widget->crop()}});
  }
  doc["sources"] = sources;
  doc["widgets"] = widgets;
  workspaces_[active_workspace_] = doc;
}

void MainWindow::persistWorkspaces() {
  if (!workspaces_.empty()) settings.workspaces = cabana::workspaceLibrary(workspaces_, active_workspace_).dump();
}

void MainWindow::applyWorkspace(Json document) {
  // Source ids are local to a saved file. A slot whose id belongs to a different open source gets its own
  // id, then slots for a route that is already open (or listed twice) merge into that source.
  const auto original = document["sources"].array_items();
  for (const auto &saved : original) {
    const auto id = saved["id"].string_value(), route = cabana::savedSourceRoute(saved);
    auto *loaded = sourceById(id);
    if (!route.empty() && loaded && !dynamic_cast<DummyStream *>(loaded) && loaded->routeName() != route)
      document = remapSource(document, id, newSourceId(document));
  }
  std::map<std::string, std::string> route_ids;
  for (auto *source : sources()) if (dynamic_cast<ReplayStream *>(source)) route_ids[source->routeName()] = source->source_id;
  const auto slots = document["sources"].array_items();
  for (const auto &saved : slots) {
    const auto id = saved["id"].string_value(), route = cabana::savedSourceRoute(saved);
    if (route.empty()) continue;
    auto [it, inserted] = route_ids.emplace(route, id);
    if (!inserted && it->second != id) document = remapSource(document, id, it->second);
  }
  workspaces_[active_workspace_] = document;
  ++workspace_generation_;
  default_workspace_ = document["default"].bool_value();
  include_routes_ = document["include_routes"].bool_value();
  playback_visible_ = document["timeline_visible"].is_null() || document["timeline_visible"].bool_value();
  playback_expanded_ = document["timeline_expanded"].is_null() || document["timeline_expanded"].bool_value();
  playback_height_ = std::clamp(document["timeline_height"].number_value(), 0., 10000.);
  camera_panes_.clear();
  for (auto &view : source_views_) {
    SourceScope scope(view->stream.get());
    view->messages_visible = view->logs_visible = view->inspector_visible = false;
    view->inspector.clear();
    // clear() also detaches the chart manager for source teardown. Workspace switches keep it.
    view->inspector.setChartsWidget(charts_widget_.get());
  }
  // Unloaded slots are placeholders until their route is opened or chosen.
  const auto &saved_sources = document["sources"].array_items();
  for (const auto &source : saved_sources) {
    const auto id = source["id"].string_value();
    if (!sourceById(id)) openStream(std::make_unique<DummyStream>(), {}, id);
    if (auto *stream = sourceById(id); dynamic_cast<DummyStream *>(stream)) stream->source_label = source["label"].string_value();
  }
  const auto rank = [&](const auto &view) {
    return std::find_if(saved_sources.begin(), saved_sources.end(), [&](const auto &s) { return s["id"] == view->stream->source_id; }) - saved_sources.begin();
  };
  if (!saved_sources.empty()) {
    std::vector<std::string> unused;
    for (const auto &view : source_views_) {
      if (dynamic_cast<DummyStream *>(view->stream.get()) && rank(view) == (int)saved_sources.size()) unused.push_back(view->stream->source_id);
    }
    for (const auto &id : unused) removeSource(id);
  }
  std::stable_sort(source_views_.begin(), source_views_.end(), [&](const auto &a, const auto &b) { return rank(a) < rank(b); });
  charts_widget_->restoreLayout(document["charts"].dump());
  pending_workspace_inspectors_.clear();
  for (const auto &source : saved_sources) if (source["inspector"].is_object()) {
    pending_workspace_inspectors_[source["id"].string_value()] = source["inspector"];
    withSource(source["id"].string_value(), [this]() { restoreSessionState(); });
  }
  for (const auto &widget : document["widgets"].array_items()) {
    const auto source = widget["source"].string_value(), kind = widget["kind"].string_value();
    withSource(source, [&]() {
      auto &view = currentSource();
      if (kind == "can") view.messages_visible = true;
      else if (kind == "logs") view.logs_visible = true;
      else if (kind == "inspector") view.inspector_visible = true;
      else if (kind == "camera") addCamera(source, (VisionStreamType)widget["camera"].int_value(), widget["crop"].bool_value(), widget["id"].string_value());
    });
  }
  timeline_.setSources(orderedSources());
  timeline_.restore(document["timeline"]);
  const auto &ui = document["ui"].string_value();
  if (!ui.empty()) ImGui::LoadIniSettingsFromMemory(ui.c_str(), ui.size());
  reset_layout_ = ui.empty();
  const auto &selected = document["selected_source"].is_string() ? document["selected_source"] : document["timeline"]["selected"];
  if (auto *source = sourceById(selected.string_value())) {
    selected_source_ = source->source_id;
    can = source;
    updateWindowTitle();
  }
}

void MainWindow::switchWorkspace(int index, bool capture_current) {
  if (index < 0 || index >= (int)workspaces_.size() || (capture_current && index == active_workspace_)) return;
  if (capture_current) captureWorkspace();
  active_workspace_ = index;
  if (cabana::isBuiltinWorkspace(workspaces_[index]) && !workspaces_[index]["builtin_initialized"].bool_value()) resetBuiltinWorkspace();
  else applyWorkspace(workspaces_[index]);
  persistWorkspaces();
  settings.save();
}

void MainWindow::importWorkspace(const std::string &path) {
  std::string error;
  const auto doc = Json::parse(util::read_file(path), error);
  if (!cabana::validWorkspace(doc)) {
    MessageBox::warning("Open Workspace", "This is not a supported Cabana workspace.");
    return;
  }
  workspaces_.push_back(cabana::customWorkspace(doc));
  switchWorkspace(workspaces_.size() - 1);
}

std::string MainWindow::sourceSlotRoute(const std::string &id) const {
  if (workspaces_.empty()) return {};
  for (const auto &saved : workspaces_[active_workspace_]["sources"].array_items())
    if (saved["id"] == id) return cabana::savedSourceRoute(saved);
  return {};
}

void MainWindow::bindSourceSlots(std::string id) {
  auto *route = dynamic_cast<ReplayStream *>(sourceById(id));
  if (!route) return;
  std::vector<std::string> slots;
  for (const auto &view : source_views_)
    if (dynamic_cast<DummyStream *>(view->stream.get()) && sourceSlotRoute(view->stream->source_id) == route->routeName())
      slots.push_back(view->stream->source_id);
  for (const auto &slot : slots) mergeSourceSlot(slot, id);
  selectSource(id);
}

void MainWindow::mergeSourceSlot(const std::string &old_id, const std::string &new_id) {
  if (!dynamic_cast<DummyStream *>(sourceById(old_id))) return;
  std::string error;
  const Json doc = remapSource(Json::object{{"charts", Json::parse(charts_widget_->serializeLayout(), error)}, {"ui", inistate::save()}}, old_id, new_id);
  // Rebind existing widgets before discarding the placeholder stream.
  charts_widget_->restoreLayout(doc["charts"].dump());
  rebindCameras(old_id, new_id);
  SourceView *from = nullptr, *to = nullptr;
  for (auto &view : source_views_) {
    if (view->stream->source_id == old_id) from = view.get();
    if (view->stream->source_id == new_id) to = view.get();
  }
  if (from && to) {
    to->messages_visible |= from->messages_visible;
    to->logs_visible |= from->logs_visible;
    to->inspector_visible |= from->inspector_visible;
  }
  if (auto pending = pending_workspace_inspectors_.extract(old_id)) pending_workspace_inspectors_[new_id] = pending.mapped();
  if (!workspaces_.empty()) workspaces_[active_workspace_] = remapSource(workspaces_[active_workspace_], old_id, new_id);
  removeSource(old_id);
  timeline_.renameSource(old_id, new_id);
  const auto &ui = doc["ui"].string_value();
  ImGui::LoadIniSettingsFromMemory(ui.c_str(), ui.size());
  withSource(new_id, [this]() { restoreSessionState(); });
}

void MainWindow::openWorkspaceRoutes(const Json &document) {
  // Route references load independently; existing tabs stay usable while loading.
  for (const auto &source : document["sources"].array_items()) {
    const auto route = source["route"].string_value(), id = source["id"].string_value();
    if (route.empty()) continue;
    // Only unloaded slots are filled; a route the user chose for a slot stays.
    if (auto *loaded = sourceById(id); loaded && !dynamic_cast<DummyStream *>(loaded)) continue;
    const auto generation = std::make_pair(workspace_generation_, ++source_load_generation_[id]);
    showStatusMessage("Opening saved routes…");
    ThreadPool::instance().run([this, alive = std::weak_ptr<bool>(alive_), source, generation]() {
      auto stream = std::make_shared<std::unique_ptr<ReplayStream>>(std::make_unique<ReplayStream>());
      const auto data_dir = source["data_dir"].string_value();
      bool ok = false;
      std::string error;
      try {
        ok = (*stream)->loadRoute(source["route"].string_value(), data_dir, REPLAY_FLAG_NONE, data_dir.empty());
      } catch (const std::exception &e) { error = e.what(); }
      utils::runOnMainThread([this, alive, stream, ok, error, source, generation]() {
        const auto slot = source["id"].string_value();
        if (alive.expired() || generation != std::make_pair(workspace_generation_, source_load_generation_[slot])) return;
        if (!ok) { MessageBox::warning("Open saved route", "Could not open " + source["route"].string_value(), error); return; }
        openStream(std::move(*stream), {}, slot);  // restores the slot's label, DBCs and alignment
        showStatusMessage("Saved route opened", 2000);
      });
    });
  }
}

void MainWindow::drawWorkspaceMenu() {
  if (!charts_widget_ || workspaces_.empty()) return;
  const auto label = "Workspace: " + workspaces_[active_workspace_]["name"].string_value() + "###WorkspaceMenu";
  if (!dropdown::BeginMenu(label.c_str())) return;
  // Presets join the list once they have been opened in this session.
  for (int i = 0; i < (int)workspaces_.size(); ++i) {
    if (workspaces_[i]["builtin"].string_value().rfind("layout:", 0) == 0 && !workspaces_[i]["builtin_initialized"].bool_value()) continue;
    ImGui::PushID(i);
    if (dropdown::Item(workspaces_[i]["name"].string_value().c_str(), nullptr, i == active_workspace_)) nextFrame([this, i]() { switchWorkspace(i); });
    ImGui::PopID();
  }
  ImGui::Separator();
  const bool builtin = cabana::isBuiltinWorkspace(workspaces_[active_workspace_]);
  std::string name = workspaces_[active_workspace_]["name"].string_value();
  ImGui::BeginDisabled(builtin);
  if (inputText("Name", &name) && !name.empty()) {
    auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = name;
    workspaces_[active_workspace_] = doc;
  }
  ImGui::EndDisabled();
  if (builtin) {
    ImGui::TextDisabled("Built-in changes last for this session. Duplicate to keep them.");
    if (dropdown::Item("Reset built-in workspace")) nextFrame([this]() { resetBuiltinWorkspace(); });
  }
  auto add = [this](const Json &doc) {
    workspaces_.push_back(doc);
    switchWorkspace(workspaces_.size() - 1);
  };
  if (dropdown::Item("New blank workspace")) nextFrame([this, add]() {
    captureWorkspace();
    Json::array slots;
    for (const auto &source : workspaces_[active_workspace_]["sources"].array_items()) slots.push_back(Json::object{{"id", source["id"]}, {"label", source["label"]}});
    add(blankWorkspace("Workspace " + std::to_string(workspaces_.size() + 1), slots));
  });
  if (dropdown::Item("Duplicate workspace")) nextFrame([this, add]() {
    captureWorkspace();
    auto doc = cabana::customWorkspace(workspaces_[active_workspace_]).object_items();
    doc["name"] = doc["name"].string_value() + " copy";
    add(doc);
  });
  if (dropdown::Item("Delete workspace", nullptr, false, !builtin)) nextFrame([this]() {
    const int removed = active_workspace_;
    switchWorkspace(0, false);
    workspaces_.erase(workspaces_.begin() + removed);
    persistWorkspaces();
    settings.save();
  });
  if (dropdown::BeginMenu("Presets")) {
    for (int i = 0; i < (int)workspaces_.size(); ++i) if (cabana::isBuiltinWorkspace(workspaces_[i])) {
      if (dropdown::Item(workspaces_[i]["name"].string_value().c_str(), nullptr, i == active_workspace_)) nextFrame([this, i]() { switchWorkspace(i); });
    }
    dropdown::EndMenu();
  }
  ImGui::Separator();
  checkBox("Include route references", &include_routes_);
  ImGui::SetItemTooltip("Save route names and source assignments. Logs and video are loaded separately.");
  if (dropdown::Item("Save workspaces")) { captureWorkspace(); persistWorkspaces(); settings.save(); }
  if (dropdown::Item("Open workspace...")) FileDialog::getOpenFileName("Open Workspace", settings.last_dir, ".json",
    [this](const std::string &path) { if (!path.empty()) nextFrame([this, path]() { importWorkspace(path); }); });
  const auto &saved_sources = workspaces_[active_workspace_]["sources"].array_items();
  const bool has_routes = std::any_of(saved_sources.begin(), saved_sources.end(), [](const auto &s) { return !s["route"].string_value().empty(); });
  if (dropdown::Item("Open saved routes", nullptr, false, has_routes)) openWorkspaceRoutes(workspaces_[active_workspace_]);
  if (dropdown::Item("Save As...")) {
    captureWorkspace();
    FileDialog::getSaveFileName("Save Workspace", settings.last_dir + "/workspace.json", ".json",
      [contents = cabana::customWorkspace(workspaces_[active_workspace_]).dump() + '\n'](const std::string &path) {
        if (path.empty()) return;
        std::ofstream out(path);
        out << contents;
        out.close();
        if (!out) MessageBox::warning("Save Workspace", "Could not write " + path);
      });
  }
  dropdown::EndMenu();
}
