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

static Json remapSource(const Json &input, const std::string &old_id, const std::string &new_id) {
  auto document = cabana::remapWorkspaceSource(input, old_id, new_id);
  auto remapped = document.object_items();
  std::string ui = document["ui"].string_value();
  auto replace = [&](const std::string &from, const std::string &to) {
    size_t pos = 0;
    while ((pos = ui.find(from, pos)) != std::string::npos) { ui.replace(pos, from.size(), to); pos += to.size(); }
  };
  for (const char *kind : {"can", "logs", "inspector"}) {
    const auto old_name = std::string("###") + kind + "_" + old_id;
    const auto new_name = std::string("###") + kind + "_" + new_id;
    replace(old_name + "]", new_name + "]");
    char old_hash[16], new_hash[16];
    snprintf(old_hash, sizeof(old_hash), "0x%08X", ImHashStr(old_name.c_str()));
    snprintf(new_hash, sizeof(new_hash), "0x%08X", ImHashStr(new_name.c_str()));
    replace(old_hash, new_hash);
  }
  remapped["ui"] = ui;
  return remapped;
}

void MainWindow::initializeWorkspaces() {
  std::string error;
  const auto library = Json::parse(settings.workspaces, error);
  const auto &saved = library["workspaces"].array_items();
  for (int i = 0; i < (int)saved.size(); ++i) {
    if (!cabana::validWorkspace(saved[i])) continue;
    if (i == library["active"].int_value()) active_workspace_ = workspaces_.size();
    workspaces_.push_back(saved[i]);
  }
  if (workspaces_.empty()) {
    workspaces_.push_back(Json::object{{"name", "Default"}, {"default", true}});
    makeDefaultWidgets();
    captureWorkspace();
  } else {
    applyWorkspace(workspaces_[active_workspace_]);
  }
}

void MainWindow::captureWorkspace() {
  if (!charts_widget_ || workspaces_.empty()) return;
  auto doc = workspaces_[active_workspace_].object_items();
  doc["cabana_workspace"] = 2;
  doc["default"] = default_workspace_;
  doc["include_routes"] = include_routes_;
  std::string error;
  doc["charts"] = Json::parse(charts_widget_->serializeLayout(), error);
  doc["ui"] = inistate::save();
  doc["timeline"] = timeline_.snapshot();
  doc["timeline_visible"] = playback_visible_;
  doc["timeline_expanded"] = playback_expanded_;
  doc["timeline_height"] = playback_height_;
  Json::array source_docs, widgets;
  for (auto &view : source_views_) {
    auto *stream = view->stream.get();
    Json::object source{{"id", stream->source_id}, {"label", stream->source_label}};
    if (include_routes_) if (auto *replay = dynamic_cast<ReplayStream *>(stream)) {
      source["route"] = replay->routeReference();
      if (!replay->dataDirectory().empty()) source["data_dir"] = replay->dataDirectory();
      Json::array dbcs;
      for (auto *file : stream->database()->nonEmptyDBCFiles()) if (!file->filename.empty()) {
        Json::array buses;
        for (int bus : stream->database()->sources(file)) buses.push_back(bus);
        dbcs.push_back(Json::object{{"file", file->filename}, {"buses", buses}});
      }
      source["dbcs"] = dbcs;
    }
    if (include_routes_ && dynamic_cast<DummyStream *>(stream)) {
      for (const auto &saved : doc["sources"].array_items()) if (saved["id"] == source["id"]) {
        for (const char *key : {"route", "data_dir", "dbcs"}) if (!saved[key].is_null()) source[key] = saved[key];
      }
    }
    if (auto pending = pending_workspace_inspectors_.find(stream->source_id); pending != pending_workspace_inspectors_.end()) {
      source["inspector"] = pending->second;
    } else if (auto *detail = view->inspector.getDetailWidget()) {
      auto [active, ids] = detail->serializeMessageIds();
      Json::array messages;
      for (const auto &id : ids) messages.push_back(id);
      source["inspector"] = Json::object{{"active", active}, {"messages", messages}};
    } else {
      source["inspector"] = Json::object{{"active", ""}, {"messages", Json::array{}}};
    }
    source_docs.push_back(source);
    auto widget = [&](const char *kind, bool visible) {
      if (visible) widgets.push_back(Json::object{{"kind", kind}, {"source", stream->source_id}});
    };
    widget("can", view->messages_visible);
    widget("logs", view->logs_visible);
    widget("inspector", view->inspector_visible);
  }
  for (const auto &camera : camera_panes_) if (camera.visible) {
    widgets.push_back(Json::object{{"kind", "camera"}, {"id", camera.id}, {"source", camera.source},
                                  {"camera", (int)camera.type}, {"crop", camera.widget->crop()}});
  }
  doc["sources"] = source_docs;
  doc["widgets"] = widgets;
  doc.erase("panels");
  workspaces_[active_workspace_] = doc;
}

void MainWindow::persistWorkspaces() {
  if (!workspaces_.empty()) settings.workspaces = Json(Json::object{{"active", active_workspace_}, {"workspaces", workspaces_}}).dump();
}

void MainWindow::applyWorkspace(const Json &saved_document) {
  auto document = saved_document;
  // Source IDs are local to a shared file. Preserve unrelated open routes by
  // giving conflicting saved slots their own identity before applying widgets.
  for (const auto &saved : saved_document["sources"].array_items()) {
    const auto old_id = saved["id"].string_value();
    auto *loaded = sourceById(old_id);
    auto *replay = dynamic_cast<ReplayStream *>(loaded);
    const auto route = cabana::savedSourceRoute(saved);
    if (!loaded || dynamic_cast<DummyStream *>(loaded) || route.empty() ||
        (replay && replay->routeName() == route)) continue;
    std::string new_id;
    do { new_id = "source" + std::to_string(next_source_id_++); }
    while (sourceById(new_id) || std::any_of(document["sources"].array_items().begin(), document["sources"].array_items().end(),
      [&](const auto &s) { return s["id"] == new_id; }));
    document = remapSource(document, old_id, new_id);
  }
  std::map<std::string, std::string> route_sources;
  for (const auto &view : source_views_) if (auto *route = dynamic_cast<ReplayStream *>(view->stream.get()))
    route_sources[route->routeName()] = route->source_id;
  const auto saved_sources_to_bind = document["sources"].array_items();
  for (const auto &saved : saved_sources_to_bind) {
    const auto route = cabana::savedSourceRoute(saved);
    if (route.empty()) continue;
    const auto id = saved["id"].string_value();
    auto [it, inserted] = route_sources.emplace(route, id);
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
    // clear() also detaches the chart manager for source teardown. Workspace
    // switches retain that manager and may restore inspector tabs immediately.
    view->inspector.setChartsWidget(charts_widget_.get());
  }
  for (const auto &source : document["sources"].array_items()) {
    const auto id = source["id"].string_value();
    if (!sourceById(id)) {
      source_to_replace_ = id;
      const bool use_default = default_workspace_;
      default_workspace_ = false;
      openStream(std::make_unique<DummyStream>());
      default_workspace_ = use_default;
    }
    if (auto *stream = sourceById(id); stream && dynamic_cast<DummyStream *>(stream)) stream->source_label = source["label"].string_value();
  }
  std::vector<std::string> unused_slots;
  for (const auto &view : source_views_) if (dynamic_cast<DummyStream *>(view->stream.get()) && source_views_.size() > 1 && !document["sources"].array_items().empty()) {
    if (std::none_of(document["sources"].array_items().begin(), document["sources"].array_items().end(), [&](const auto &saved) { return saved["id"] == view->stream->source_id; }))
      unused_slots.push_back(view->stream->source_id);
  }
  for (const auto &id : unused_slots) removeSource(id);
  const auto &saved_sources = document["sources"].array_items();
  const auto source_rank = [&](const auto &view) {
    return std::find_if(saved_sources.begin(), saved_sources.end(), [&](const auto &saved) {
      return saved["id"] == view->stream->source_id;
    }) - saved_sources.begin();
  };
  std::stable_sort(source_views_.begin(), source_views_.end(), [&](const auto &a, const auto &b) { return source_rank(a) < source_rank(b); });
  charts_widget_->restoreLayout(document["charts"].dump(), true);
  pending_workspace_inspectors_.clear();
  for (const auto &source : document["sources"].array_items()) if (source["inspector"].is_object()) {
    const auto id = source["id"].string_value();
    pending_workspace_inspectors_[id] = source["inspector"];
    withSource(id, [this]() { restoreSessionState(); });
  }
  if (document["cabana_workspace"] == 1) {
    auto &view = currentSource();
    view.messages_visible = document["panels"]["messages"].bool_value();
    view.logs_visible = document["panels"]["logs"].bool_value();
    view.inspector_visible = document["panels"]["details"].bool_value();
    default_workspace_ = true;
    reset_layout_ = true;
  } else {
    for (const auto &widget : document["widgets"].array_items()) {
      const auto source = widget["source"].string_value();
      withSource(source, [&]() {
        auto &view = currentSource();
        const auto kind = widget["kind"].string_value();
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
  }
}

void MainWindow::switchWorkspace(int index, bool capture_current) {
  if (index < 0 || index >= (int)workspaces_.size() || (capture_current && index == active_workspace_)) return;
  if (capture_current) captureWorkspace();
  active_workspace_ = index;
  applyWorkspace(workspaces_[index]);
  persistWorkspaces();
  settings.save();
}

void MainWindow::importWorkspace(const std::string &path) {
  std::string error;
  const auto doc = Json::parse(util::read_file(path), error);
  if (!error.empty() || !cabana::validWorkspace(doc)) {
    MessageBox::warning("Open Workspace", "This is not a supported Cabana workspace.");
    return;
  }
  workspaces_.push_back(doc);
  switchWorkspace(workspaces_.size() - 1);
}

std::string MainWindow::sourceSlotRoute(const std::string &id) const {
  if (!workspaces_.empty()) {
    for (const auto &saved : workspaces_[active_workspace_]["sources"].array_items())
      if (saved["id"] == id) return cabana::savedSourceRoute(saved);
  }
  auto *source = sourceById(id);
  return source ? cabana::savedSourceRoute(Json::object{{"label", source->source_label}}) : std::string();
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
  auto *old = sourceById(old_id);
  if (!old || !dynamic_cast<DummyStream *>(old)) return;
  std::string error;
  Json doc = Json::object{{"charts", Json::parse(charts_widget_->serializeLayout(), error)},
                        {"timeline", timeline_.snapshot()}, {"ui", inistate::save()}};
  doc = remapSource(doc, old_id, new_id);
  // Rebind existing widgets before discarding the placeholder stream.
  charts_widget_->restoreLayout(doc["charts"].dump(), true);
  for (auto &camera : camera_panes_) if (camera.source == old_id) {
    const bool crop = camera.widget->crop();
    camera.source = new_id;
    camera.widget = std::make_unique<VideoWidget>(sourceById(new_id), camera.type);
    camera.widget->setCrop(crop);
    camera.widget->togglePlayback = [this, new_id, type = camera.type]() {
      timeline_.selectSource(new_id, type);
      timeline_.togglePlayback();
    };
  }
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
  if (auto pending = pending_workspace_inspectors_.find(old_id); pending != pending_workspace_inspectors_.end()) {
    pending_workspace_inspectors_[new_id] = pending->second;
    pending_workspace_inspectors_.erase(pending);
  }
  if (!workspaces_.empty()) workspaces_[active_workspace_] = remapSource(workspaces_[active_workspace_], old_id, new_id);
  removeSource(old_id);
  timeline_.restore(doc["timeline"]);
  const auto ui = doc["ui"].string_value();
  ImGui::LoadIniSettingsFromMemory(ui.c_str(), ui.size());
  withSource(new_id, [this]() { restoreSessionState(); });
}

void MainWindow::openWorkspaceRoutes(const Json &document) {
  // Route references are resolved independently; existing tabs stay usable while loading.
  for (const auto &source : document["sources"].array_items()) {
    const auto route = source["route"].string_value();
    if (route.empty()) continue;
    const auto id = source["id"].string_value();
    if (auto *loaded = dynamic_cast<ReplayStream *>(sourceById(id)); loaded && loaded->routeName() == Route::parseRoute(route).str) continue;
    const auto workspace_generation = workspace_generation_;
    const auto source_generation = ++source_load_generation_[id];
    showStatusMessage("Opening saved routes…");
    ThreadPool::instance().run([this, alive = std::weak_ptr<bool>(alive_), source, document, workspace_generation, source_generation]() {
      auto stream = std::make_shared<std::unique_ptr<ReplayStream>>(std::make_unique<ReplayStream>());
      bool ok = false;
      std::string error;
      try {
        ok = (*stream)->loadRoute(source["route"].string_value(), source["data_dir"].string_value(), REPLAY_FLAG_NONE,
                                  source["data_dir"].string_value().empty());
      } catch (const std::exception &e) { error = e.what(); }
      utils::runOnMainThread([this, alive, stream, ok, error, source, document, workspace_generation, source_generation]() mutable {
        if (alive.expired()) return;
        if (workspace_generation != workspace_generation_ || source_load_generation_[source["id"].string_value()] != source_generation) return;
        if (!ok) { MessageBox::warning("Open saved route", "Could not open " + source["route"].string_value(), error); return; }
        const bool already_loaded = std::any_of(source_views_.begin(), source_views_.end(), [&](const auto &view) {
          auto *loaded = dynamic_cast<ReplayStream *>(view->stream.get());
          return loaded && loaded->routeName() == (*stream)->routeName();
        });
        source_to_replace_ = source["id"].string_value();
        const bool use_default = default_workspace_;
        default_workspace_ = false;
        openStream(std::move(*stream));
        if (already_loaded) {
          default_workspace_ = use_default;
          return;
        }
        for (const auto &saved : source["dbcs"].array_items()) {
          const std::string path = saved.is_string() ? saved.string_value() : saved["file"].string_value();
          SourceSet buses;
          for (const auto &bus : saved["buses"].array_items()) buses.insert(bus.int_value());
          if (buses.empty()) buses = SOURCE_ALL;
          if (std::filesystem::exists(path)) loadFile(path, buses);
        }
        default_workspace_ = use_default;
        can->source_label = source["label"].string_value();
        const auto &current_document = workspaces_[active_workspace_];
        timeline_.restore(current_document["timeline"]);
        showStatusMessage("Saved route opened", 2000);
      });
    });
  }
}

void MainWindow::loadWorkspacePreset(const std::string &path) {
  std::string error;
  auto layout = Json::parse(util::read_file(path), error);
  if (!chart::parseLayout(layout.dump())) { MessageBox::warning("Workspace preset", "Unsupported preset."); return; }
  captureWorkspace();
  auto doc = workspaces_[active_workspace_].object_items();
  doc["name"] = std::filesystem::path(path).stem().string();
  doc["charts"] = layout;
  doc["ui"] = "";
  doc["default"] = false;
  workspaces_.push_back(doc);
  switchWorkspace(workspaces_.size() - 1);
}

void MainWindow::drawWorkspaceMenu() {
  if (!charts_widget_ || workspaces_.empty()) return;
  const auto label = "Workspace: " + workspaces_[active_workspace_]["name"].string_value() + "###WorkspaceMenu";
  if (!dropdown::BeginMenu(label.c_str())) return;
  for (int i = 0; i < (int)workspaces_.size(); ++i) {
    ImGui::PushID(i);
    if (dropdown::Item(workspaces_[i]["name"].string_value().c_str(), nullptr, i == active_workspace_)) nextFrame([this, i]() { switchWorkspace(i); });
    ImGui::PopID();
  }
  ImGui::Separator();
  std::string name = workspaces_[active_workspace_]["name"].string_value();
  if (inputText("Name", &name) && !name.empty()) {
    auto doc = workspaces_[active_workspace_].object_items(); doc["name"] = name; workspaces_[active_workspace_] = doc;
  }
  if (dropdown::Item("New blank workspace")) nextFrame([this]() {
    captureWorkspace();
    auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = "Workspace " + std::to_string(workspaces_.size() + 1);
    doc["ui"] = ""; doc["widgets"] = Json::array{}; doc["default"] = false; doc["include_routes"] = false;
    doc["timeline"] = Json::object{};
    Json::array source_slots;
    for (const auto &source : doc["sources"].array_items()) source_slots.push_back(Json::object{{"id", source["id"]}, {"label", source["label"]}});
    doc["sources"] = source_slots;
    doc["charts"] = Json::object{{"cabana_layout", 3}, {"columns", 1}, {"range", 60}, {"tabs", Json::array{Json::array{}}}};
    workspaces_.push_back(doc); switchWorkspace(workspaces_.size() - 1);
  });
  if (dropdown::Item("Duplicate workspace")) nextFrame([this]() {
    captureWorkspace(); auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = doc["name"].string_value() + " copy";
    workspaces_.push_back(doc); switchWorkspace(workspaces_.size() - 1);
  });
  if (dropdown::Item("Delete workspace", nullptr, false, active_workspace_ != 0)) nextFrame([this]() {
    const int removed = active_workspace_; switchWorkspace(0);
    workspaces_.erase(workspaces_.begin() + removed); persistWorkspaces(); settings.save();
  });
  if (dropdown::BeginMenu("Presets")) {
    for (const bool live : {false, true}) if (dropdown::Item(live ? "Live" : "Default")) nextFrame([this, live]() {
      captureWorkspace();
      auto doc = workspaces_[active_workspace_].object_items();
      doc["name"] = live ? "Live" : "Default";
      doc["ui"] = "";
      doc["widgets"] = Json::array{};
      doc["default"] = !live;
      doc["include_routes"] = false;
      doc["timeline"] = Json::object{};
      doc["charts"] = Json::object{{"cabana_layout", 4}, {"range", 60}, {"charts", Json::array{}}};
      Json::array slots;
      for (const auto &source : doc["sources"].array_items()) slots.push_back(Json::object{{"id", source["id"]}, {"label", source["label"]}});
      std::string live_source;
      if (live) {
        for (const auto &view : source_views_) if (view->stream->liveStreaming() && !dynamic_cast<DummyStream *>(view->stream.get())) {
          live_source = view->stream->source_id;
          break;
        }
        if (live_source.empty()) {
          do { live_source = "source" + std::to_string(next_source_id_++); } while (sourceById(live_source));
          slots.push_back(Json::object{{"id", live_source}, {"label", "Live source"}});
        }
      }
      doc["sources"] = slots;
      workspaces_.push_back(doc);
      switchWorkspace(workspaces_.size() - 1);
      if (live) {
        selectSource(live_source);
        auto &view = currentSource();
        view.messages_visible = view.logs_visible = view.inspector_visible = true;
        charts_widget_->newChart();
        reset_layout_ = true;
        showStatusMessage("Add a Device, Panda, or SocketCAN source to start live inspection.", 5000);
      } else makeDefaultWidgets();
    });
    ImGui::Separator();
    std::error_code error;
    for (const auto &entry : std::filesystem::directory_iterator(executableDir() / "layouts", error)) if (entry.path().extension() == ".json")
      if (dropdown::Item(entry.path().stem().c_str())) nextFrame([this, path = entry.path().string()]() { loadWorkspacePreset(path); });
    dropdown::EndMenu();
  }
  ImGui::Separator();
  checkBox("Include route references", &include_routes_);
  ImGui::SetItemTooltip("Save route names and source assignments. Logs and video are loaded separately.");
  if (dropdown::Item("Save workspaces")) { captureWorkspace(); persistWorkspaces(); settings.save(); }
  if (dropdown::Item("Open workspace...")) FileDialog::getOpenFileName("Open Workspace", settings.last_dir, ".json",
    [this](const std::string &path) { if (!path.empty()) nextFrame([this, path]() { importWorkspace(path); }); });
  bool has_routes = false;
  for (const auto &source : workspaces_[active_workspace_]["sources"].array_items()) has_routes |= !source["route"].string_value().empty();
  if (dropdown::Item("Open saved routes", nullptr, false, has_routes)) openWorkspaceRoutes(workspaces_[active_workspace_]);
  if (dropdown::Item("Save As...")) {
    captureWorkspace();
    FileDialog::getSaveFileName("Save Workspace", settings.last_dir + "/workspace.json", ".json",
      [contents = workspaces_[active_workspace_].dump() + '\n'](const std::string &path) {
        if (path.empty()) return;
        std::ofstream out(path); out << contents; out.close();
        if (!out) MessageBox::warning("Save Workspace", "Could not write " + path);
      });
  }
  dropdown::EndMenu();
}
