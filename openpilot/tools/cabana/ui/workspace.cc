#include "tools/cabana/ui/mainwin.h"

#include <fstream>

#include "common/util.h"
#include "tools/cabana/settings.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/ui/dialogs/messagebox.h"
#include "tools/cabana/ui/inistate.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/workspace.h"

using json11::Json;

void MainWindow::initializeWorkspaces() {
  if (workspaces_.empty()) {
    std::string error;
    const auto library = Json::parse(settings.workspaces, error);
    const auto &saved = library["workspaces"].array_items();
    for (int i = 0; i < (int)saved.size(); ++i) {
      if (!cabana::validWorkspace(saved[i])) continue;
      if (i == library["active"].int_value()) active_workspace_ = workspaces_.size();
      workspaces_.push_back(saved[i]);
    }
    if (workspaces_.empty()) {
      workspaces_.push_back(Json::object{{"name", "Default"}});
      captureWorkspace();
      return;
    }
    // Apply the selected workspace once; route changes only need to rebuild charts.
    switchWorkspace(active_workspace_, false);
    return;
  }
  pending_workspace_layout_ = workspaces_[active_workspace_]["charts"].dump();
}

void MainWindow::captureWorkspace() {
  if (!charts_widget_ || workspaces_.empty()) return;
  auto doc = workspaces_[active_workspace_].object_items();
  doc["cabana_workspace"] = 1;
  std::string error;
  doc["charts"] = Json::parse(pending_workspace_layout_.empty() ? charts_widget_->serializeLayout() : pending_workspace_layout_, error);
  doc["ui"] = inistate::save();
  doc["panels"] = Json::object{{"messages", messages_visible_}, {"logs", log_messages_visible_},
    {"charts", charts_visible_}, {"video", video_visible_}, {"details", details_visible_}, {"playback", playback_visible_}};
  workspaces_[active_workspace_] = doc;
}

void MainWindow::persistWorkspaces() {
  if (workspaces_.empty()) return;
  settings.workspaces = Json(Json::object{{"active", active_workspace_}, {"workspaces", workspaces_}}).dump();
}

void MainWindow::switchWorkspace(int index, bool capture_current) {
  if (!charts_widget_ || index < 0 || index >= (int)workspaces_.size()) return;
  if (capture_current) {
    if (index == active_workspace_) return;
    captureWorkspace();
  }
  const auto target = workspaces_[index];
  active_workspace_ = index;
  pending_workspace_layout_ = target["charts"].dump();
  charts_widget_->removeAll();
  const auto status = charts_widget_->restoreLayout(pending_workspace_layout_, true);
  if (status == ChartsWidget::LayoutStatus::Restored) pending_workspace_layout_.clear();
  else showStatusMessage("Workspace is waiting for its matching DBC.", 5000);
  const auto &ui = target["ui"].string_value();
  if (!ui.empty()) ImGui::LoadIniSettingsFromMemory(ui.c_str(), ui.size());
  reset_layout_ = ui.empty();
  const auto &panels = target["panels"];
  messages_visible_ = panels["messages"].bool_value();
  log_messages_visible_ = panels["logs"].bool_value();
  charts_visible_ = panels["charts"].bool_value();
  video_visible_ = panels["video"].bool_value();
  details_visible_ = panels["details"].bool_value();
  playback_visible_ = panels["playback"].bool_value();
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

void MainWindow::drawWorkspaceMenu() {
  if (!charts_widget_ || workspaces_.empty()) return;
  const auto label = "Workspace: " + workspaces_[active_workspace_]["name"].string_value() + "###WorkspaceMenu";
  if (!dropdown::BeginMenu(label.c_str())) return;
  for (int i = 0; i < (int)workspaces_.size(); ++i) {
    ImGui::PushID(i);
    if (dropdown::Item(workspaces_[i]["name"].string_value().c_str(), nullptr, i == active_workspace_))
      nextFrame([this, i]() { switchWorkspace(i); });
    ImGui::PopID();
  }
  ImGui::Separator();
  std::string name = workspaces_[active_workspace_]["name"].string_value();
  if (inputText("Name", &name) && !name.empty()) {
    auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = name;
    workspaces_[active_workspace_] = doc;
  }
  if (dropdown::Item("New blank workspace")) nextFrame([this]() {
    captureWorkspace();
    auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = "Workspace " + std::to_string(workspaces_.size() + 1);
    doc["ui"] = "";
    doc["panels"] = Json::object{{"messages", true}, {"logs", true}, {"charts", true},
                                {"video", true}, {"details", false}, {"playback", true}};
    doc["charts"] = Json::object{{"cabana_layout", 3}, {"columns", 1}, {"range", 60}, {"tabs", Json::array{Json::array{}}}};
    workspaces_.push_back(doc);
    switchWorkspace(workspaces_.size() - 1);
  });
  if (dropdown::Item("Duplicate workspace")) nextFrame([this]() {
    captureWorkspace();
    auto doc = workspaces_[active_workspace_].object_items();
    doc["name"] = doc["name"].string_value() + " copy";
    workspaces_.push_back(doc);
    switchWorkspace(workspaces_.size() - 1);
  });
  if (dropdown::Item("Delete workspace", nullptr, false, active_workspace_ != 0)) nextFrame([this]() {
    const int removed = active_workspace_;
    switchWorkspace(0);
    workspaces_.erase(workspaces_.begin() + removed);
    persistWorkspaces();
    settings.save();
  });
  ImGui::Separator();
  if (dropdown::Item("Save workspaces")) {
    captureWorkspace();
    persistWorkspaces();
    settings.save();
  }
  if (dropdown::Item("Open...")) FileDialog::getOpenFileName("Open Workspace", settings.last_dir, ".json",
    [this](const std::string &path) { if (!path.empty()) nextFrame([this, path]() { importWorkspace(path); }); });
  if (dropdown::Item("Save As...")) {
    captureWorkspace();
    FileDialog::getSaveFileName("Save Workspace", settings.last_dir + "/workspace.json", ".json",
      [contents = workspaces_[active_workspace_].dump() + '\n'](const std::string &path) {
        if (path.empty()) return;
        std::ofstream out(path);
        out << contents;
        out.close();
        if (!out) MessageBox::warning("Save Workspace", "Could not write " + path);
      });
  }
  dropdown::EndMenu();
}
