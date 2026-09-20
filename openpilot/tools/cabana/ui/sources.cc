#include "tools/cabana/ui/mainwin.h"

#include <algorithm>
#include <cassert>

#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"

MainWindow::SourceView &MainWindow::currentSource() {
  for (auto &view : source_views_) if (view->stream.get() == can) return *view;
  for (auto &view : source_views_) if (view->stream->source_id == selected_source_) return *view;
  assert(!source_views_.empty());
  return *source_views_.front();
}

std::vector<AbstractStream *> MainWindow::orderedSources() const {
  std::vector<AbstractStream *> result;
  for (const auto &view : source_views_) result.push_back(view->stream.get());
  return result;
}

void MainWindow::withSource(const std::string &id, std::function<void()> fn) {
  if (auto *source = sourceById(id)) {
    SourceScope scope(source);
    fn();
  }
}

void MainWindow::nextFrame(std::function<void()> fn) {
  const std::string id = can ? can->source_id : "";
  next_frame_.push_back([this, id, fn = std::move(fn)]() {
    if (id.empty()) fn();
    else withSource(id, fn);
  });
}

void MainWindow::selectSource(const std::string &id) {
  if (auto *source = sourceById(id)) {
    selected_source_ = id;
    can = source;
    timeline_.selectSource(id);
    updateWindowTitle();
  }
}

std::string MainWindow::panelName(const char *kind) const {
  const std::string title = std::string(kind) == "can" ? "CAN" : std::string(kind) == "logs" ? "Messages" : "Inspector";
  return title + " · " + can->source_label + "###" + kind + "_" + can->source_id;
}

void MainWindow::removeSource(const std::string &id) {
  ++source_load_generation_[id];
  if (charts_widget_) charts_widget_->removeSource(id);
  camera_panes_.erase(std::remove_if(camera_panes_.begin(), camera_panes_.end(), [&](const auto &p) { return p.source == id; }), camera_panes_.end());
  const auto found = std::find_if(source_views_.begin(), source_views_.end(), [&](const auto &v) { return v->stream->source_id == id; });
  if (found == source_views_.end()) return;
  {
    auto &view = **found;
    SourceScope scope(view.stream.get());
    view.tools.clear();
    view.connections.clear();
    view.inspector.clear();
    view.messages.reset();
    unregisterSource(view.stream.get());
  }
  can = &dummy_;
  source_views_.erase(found);
  if (source_views_.empty()) openStream(std::make_unique<DummyStream>());
  selectSource(source_views_.front()->stream->source_id);
  timeline_.setSources(orderedSources());
  showStatusMessage("Source closed", 2000);
}

void MainWindow::addCamera(const std::string &source_id, VisionStreamType type, bool crop, const std::string &id) {
  auto *source = sourceById(source_id);
  if (!source) return;
  SourceScope scope(source);
  CameraPane pane;
  pane.id = id;
  if (pane.id.empty()) do {
    pane.id = "camera" + std::to_string(next_camera_id_++);
  } while (std::any_of(camera_panes_.begin(), camera_panes_.end(), [&](const auto &p) { return p.id == pane.id; }));
  pane.source = source_id;
  pane.type = type;
  pane.widget = std::make_unique<VideoWidget>(source, type);
  pane.widget->setCrop(crop);
  pane.widget->togglePlayback = [this, source_id, type]() {
    timeline_.selectSource(source_id, type);
    timeline_.togglePlayback();
  };
  if (id.empty()) dockNewPanel("###camera_" + pane.id);
  camera_panes_.push_back(std::move(pane));
  if (!source->liveStreaming()) source->seekTo(source->currentSec());
}

void MainWindow::makeDefaultWidgets() {
  auto &view = currentSource();
  view.messages_visible = true;
  view.logs_visible = true;
  const auto available = VideoWidget::availableStreams(can);
  if (!available.empty() && std::none_of(camera_panes_.begin(), camera_panes_.end(), [&](const auto &p) { return p.source == can->source_id; }))
    addCamera(can->source_id, *available.begin());
  if (charts_widget_ && charts_widget_->chartCount() == 0) charts_widget_->newChart();
  reset_layout_ = true;
}

void MainWindow::drawAddWidgetMenu() {
  if (dropdown::Item("Chart")) nextFrame([this]() { charts_widget_->newChart(); });
  ImGui::Separator();
  if (sources().size() > 1) {
    ImGui::TextDisabled("Source");
    std::vector<std::string> labels;
    int selected = 0;
    for (int i = 0; i < (int)sources().size(); ++i) {
      labels.push_back(sources()[i]->source_label);
      if (sources()[i]->source_id == selected_source_) selected = i;
    }
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 22);
    if (comboBox("##widget_source", &selected, labels)) selectSource(sources()[selected]->source_id);
  }
  SourceScope scope(sourceById(selected_source_));
  auto &view = currentSource();
  if (dropdown::Item("CAN messages")) { view.messages_visible = true; selectPanelTab(panelName("can").c_str()); }
  if (dropdown::Item("openpilot messages")) { view.logs_visible = true; selectPanelTab(panelName("logs").c_str()); }
  if (dropdown::Item("CAN inspector")) { view.inspector_visible = true; selectPanelTab(panelName("inspector").c_str()); }
  ImGui::Separator();
  const auto available = VideoWidget::availableStreams(can);
  for (auto type : available) {
    if (dropdown::Item(VideoWidget::cameraName(type))) {
      const auto source = can->source_id;
      nextFrame([this, source, type]() { addCamera(source, type); });
    }
  }
  if (available.empty()) {
    ImGui::TextDisabled(hasStream() ? "No camera files in this source" : "Open a route to add its cameras");
  }
}

void MainWindow::drawSourcesMenu() {
  const auto label = "Sources (" + std::to_string(source_views_.size()) + ")";
  if (!dropdown::BeginMenu(label.c_str())) return;
  if (dropdown::Item("Add route or live source...")) selectAndOpenStream();
  ImGui::Separator();
  for (auto &view : source_views_) {
    auto *source = view->stream.get();
    ImGui::PushID(source->source_id.c_str());
    if (dropdown::Item(source->source_label.c_str(), nullptr, source->source_id == selected_source_)) selectSource(source->source_id);
    ImGui::SetItemTooltip("%s", source->routeName().c_str());
    ImGui::PopID();
  }
  ImGui::Separator();
  if (auto *source = sourceById(selected_source_)) {
    std::string name = source->source_label;
    if (inputText("Name", &name) && !name.empty()) source->source_label = name;
    if (dynamic_cast<DummyStream *>(source)) {
      if (dropdown::Item("Choose route for this source...")) {
        source_to_replace_ = source->source_id;
        selectAndOpenStream();
      }
    } else if (dropdown::Item("Close selected source")) closeStream();
  }
  dropdown::EndMenu();
}
