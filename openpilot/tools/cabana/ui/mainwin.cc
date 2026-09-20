#include "tools/cabana/ui/mainwin.h"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include <GLFW/glfw3.h>

#include "json11/json11.hpp"
#include "tools/cabana/commands.h"
#include "tools/cabana/settings.h"
#include "tools/cabana/ui/app.h"
#include "tools/cabana/ui/dialogs/filedialog.h"
#include "tools/cabana/ui/dialogs/messagebox.h"
#include "tools/cabana/ui/inistate.h"
#include "tools/cabana/ui/threadpool.h"
#include "tools/cabana/ui/tools/findsignal.h"
#include "tools/cabana/ui/tools/findsimilarbits.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/widgets/scrollabletabbar.h"
#include "tools/cabana/utils/export.h"
#include "tools/cabana/utils/util.h"
#include "tools/replay/py_downloader.h"
#include "tools/replay/util.h"

namespace {
// dock window ids (the visible titles change, the part after ### is the identity)
constexpr const char *VIDEO_PANEL = "###VideoPanel";
constexpr const char *CENTER_PANEL = "CAN Details###CenterWidget";
constexpr const char *CHARTS_PANEL = "Charts###ChartsPanel";
constexpr const char *LOG_MESSAGES_PANEL = "openpilot Messages###LogMessagesPanel";
}  // namespace

MainWindow::MainWindow(GLFWwindow *window, std::unique_ptr<AbstractStream> stream, StreamLoader stream_loader,
                       const std::string &dbc_file, const std::string &layout) : startup_layout_(layout), window_(window) {
  can = &dummy_;
  reset_layout_ = true;
  loadFingerprints();
  std::error_code ec;
  for (const auto &entry : std::filesystem::directory_iterator(OPENDBC_FILE_PATH, ec)) {
    if (entry.is_regular_file() && entry.path().extension() == ".dbc") {
      opendbc_names_.push_back(entry.path().filename().string());
    }
  }
  std::sort(opendbc_names_.begin(), opendbc_names_.end());

  // download handlers are called from download threads
  installDownloadProgressHandler([this](uint64_t cur, uint64_t total, bool success) {
    utils::runOnMainThread([this, cur, total, success]() { updateDownloadProgress(cur, total, success); });
  });
  installMessageHandler([this](ReplyMsgType type, const std::string &msg) {
    utils::runOnMainThread([this, msg]() { showStatusMessage(msg, 2000); });
  });

  openStream(std::make_unique<DummyStream>());
  charts_widget_ = std::make_unique<ChartsWidget>();
  currentSource().inspector.setChartsWidget(charts_widget_.get());
  charts_widget_->seekRequested = [this](double seconds) { timeline_.seek(seconds); };
  charts_widget_->pauseRequested = [this](bool paused) { timeline_.setPaused(paused); };
  connections_.push_back(charts_widget_->showLogMessages.connect([this]() {
    currentSource().logs_visible = true;
    selectPanelTab(panelName("logs").c_str());
  }));
  initializeWorkspaces();

  startup_stream_ = std::move(stream);
  startup_loader_ = std::move(stream_loader);
  nextFrame([this, dbc_file]() {
    if (startup_loader_) {
      loadStartupStream(dbc_file);
    } else {
      if (startup_stream_) openStream(std::move(startup_stream_), dbc_file);
    }
  });
}

void MainWindow::loadFingerprints() {
  std::ifstream json_file((executableDir() / "dbc/car_fingerprint_to_dbc.json"));
  if (!json_file) return;
  const std::string contents{std::istreambuf_iterator<char>(json_file), std::istreambuf_iterator<char>()};
  std::string err;
  auto doc = json11::Json::parse(contents, err);
  if (!err.empty() || !doc.is_object()) return;
  for (const auto &kv : doc.object_items()) {
    if (kv.second.is_string()) {
      fingerprint_to_dbc_.emplace(kv.first, kv.second.string_value());
    }
  }
}

void MainWindow::drawFileMenu() {
  const bool has_stream = hasStream();
  if (dropdown::Item("Add source...")) selectAndOpenStream();
  if (dropdown::Item("Close selected source", nullptr, false, has_stream)) closeStream();
  if (dropdown::Item("Export to CSV...", nullptr, false, has_stream)) exportToCSV();
  ImGui::Separator();

  if (dropdown::Item("New DBC File", shortcut("N").c_str())) newFile();
  if (dropdown::Item("Open DBC File...", shortcut("O").c_str())) openFile();

  if (dropdown::BeginMenu("Manage DBC Files", has_stream)) {
    drawManageDBCsMenu();
    dropdown::EndMenu();
  }
  if (dropdown::BeginMenu("Open Recent")) {
    drawRecentFilesMenu();
    dropdown::EndMenu();
  }

  ImGui::Separator();
  if (dropdown::BeginMenu("Load DBC from commaai/opendbc")) {
    for (const auto &name : opendbc_names_) {
      if (dropdown::Item(name.c_str())) loadDBCFromOpendbc(name);
    }
    dropdown::EndMenu();
  }
  if (dropdown::Item("Load DBC from Clipboard")) loadFromClipboard();

  ImGui::Separator();
  const int cnt = dbc()->nonEmptyDBCCount();
  const std::string save_text = cnt > 1 ? "Save " + std::to_string(cnt) + " DBCs..." : "Save DBC...";
  if (dropdown::Item(save_text.c_str(), shortcut("S").c_str(), false, cnt > 0)) save();
  if (dropdown::Item("Save DBC As...", shortcut("Shift+S").c_str(), false, cnt == 1)) saveAs();
  // TODO: Support clipboard for multiple files
  if (dropdown::Item("Copy DBC to Clipboard", nullptr, false, cnt == 1)) saveToClipboard();

  ImGui::Separator();
  if (dropdown::Item("Settings...")) openSettings();

  ImGui::Separator();
  if (dropdown::Item("Exit", shortcut("Q").c_str())) close();
}

void MainWindow::drawMenuBar() {
  // Avoid a double border with the separator drawn below.
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  const ImVec2 padding = ImGui::GetStyle().FramePadding;
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(padding.x, padding.y * 1.75f));
  const bool open = ImGui::BeginMainMenuBar();
  ImGui::PopStyleVar(2);
  if (!open) return;
  // Menu items extend their hit area by half ItemSpacing; cover the full bar height.
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                      ImVec2(ImGui::GetStyle().ItemSpacing.x, ImGui::GetWindowHeight() - ImGui::GetTextLineHeight()));
  if (dropdown::BeginMenu("File")) {
    drawFileMenu();
    dropdown::EndMenu();
  }

  if (dropdown::BeginMenu("Edit")) {
    auto stack = UndoStack::instance();
    const std::string undo_text = stack->canUndo() ? "Undo " + stack->undoText() : "Undo";
    const std::string redo_text = stack->canRedo() ? "Redo " + stack->redoText() : "Redo";
    if (dropdown::Item(undo_text.c_str(), shortcut("Z").c_str(), false, stack->canUndo())) stack->undo();
    if (dropdown::Item(redo_text.c_str(), shortcut("Shift+Z").c_str(), false, stack->canRedo())) stack->redo();
    dropdown::EndMenu();
  }

  drawWorkspaceMenu();
  if (dropdown::BeginMenu("Analysis")) {
    charts_widget_->drawAnalysisMenu();
    dropdown::EndMenu();
  }

  if (dropdown::BeginMenu("View")) {
    if (dropdown::Item("Full Screen", shortcut("F11").c_str())) toggleFullScreen();
    ImGui::Separator();
    dropdown::Item("Timeline", nullptr, &playback_visible_);
    if (dropdown::Item("Arrange widgets")) reset_layout_ = true;
    dropdown::EndMenu();
  }

  if (dropdown::BeginMenu("Tools", hasStream())) {
    if (dropdown::Item("Find Similar Bits")) findSimilarBits();
    if (dropdown::Item("Find Signal")) findSignal();
    dropdown::EndMenu();
  }

  if (dropdown::BeginMenu("Help")) {
    if (dropdown::Item("Help", "F1")) toggleHelp();
    dropdown::EndMenu();
  }
  ImGui::PopStyleVar();
  drawSourcesMenu();
  drawPanelToggles();
  const ImVec2 min = ImGui::GetWindowPos();
  const ImVec2 max(min.x + ImGui::GetWindowWidth(), min.y + ImGui::GetWindowHeight());
  ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(min.x, max.y - 1.0f), max, ImGui::GetColorU32(ImGuiCol_Border));
  ImGui::EndMainMenuBar();
}

void MainWindow::createDockWidgets() {
  auto &source = currentSource();
  source.messages = std::make_unique<MessagesWidget>();
  source.inspector.setChartsWidget(charts_widget_.get());
  const std::string id = can->source_id;
  source.connections.push_back(source.messages->msgSelectionChanged.connect([this, id](const MessageId &message) {
    withSource(id, [this, message]() { showMessage(message); });
  }));
}

void MainWindow::showStatusMessage(const std::string &msg, int timeout_ms) {
  status_bar_.message = msg;
  status_bar_.message_until = timeout_ms > 0 ? ImGui::GetTime() + timeout_ms / 1000.0 : 0;
}

void MainWindow::updateWindowTitle() {
  std::string title;
  for (auto f : dbc()->nonEmptyDBCFiles()) {
    if (!title.empty()) title += " | ";
    title += "(" + toString(dbc()->sources(f)) + ") " + f->name();
  }
  if (window_modified_) title += "*";
  if (hasStream()) {
    const std::string stream_title = can->liveStreaming() ? "Live Stream" : can->routeName();
    title = title.empty() ? stream_title : stream_title + " \xe2\x80\x94 " + title;
  }
  if (!title.empty()) title += " \xe2\x80\x94 ";  // em dash separator
  title += "Cabana";
  glfwSetWindowTitle(window_, title.c_str());
}

void MainWindow::dbcFileChanged() {
  UndoStack::instance()->clear();
  updateWindowTitle();
  nextFrame([this]() { restoreSessionState(); });
}

void MainWindow::selectAndOpenStream() {
  stream_selector_.open([this](std::unique_ptr<AbstractStream> stream, const std::string &dbc_file) {
    if (stream) openStream(std::move(stream), dbc_file);
  });
}

// the route file listing hits the comma API, so the loader runs on a worker behind the window
void MainWindow::loadStartupStream(const std::string &dbc_file) {
  wait_dlg_.text = "Loading route...";
  wait_dlg_.value = 0;
  wait_dlg_.open = true;
  wait_dlg_.show_at = ImGui::GetTime() + 4.0;  // minimum duration before the dialog shows
  ThreadPool::instance().run([this, dbc_file, loader = std::move(startup_loader_)]() {
    AbstractStream *loaded = nullptr;
    std::string error;
    try {
      loaded = loader().release();
    } catch (const std::exception &e) {
      // the pool swallows exceptions, so the wait dialog would spin forever
      error = e.what();
    }
    utils::runOnMainThread([this, dbc_file, loaded, error]() {
      wait_dlg_.open = false;
      std::unique_ptr<AbstractStream> stream(loaded);
      if (!error.empty()) {
        fprintf(stderr, "%s\n", error.c_str());
        MessageBox::warning("Failed to load route", error);
      }
      stream ? openStream(std::move(stream), dbc_file) : openStream(std::make_unique<DummyStream>());
    });
  });
}

void MainWindow::closeStream() {
  const std::string id = can->source_id;
  remindSaveChanges([this, id]() { nextFrame([this, id]() { removeSource(id); }); });
}

void MainWindow::exportToCSV() {
  std::string dir = settings.last_dir + "/" + can->routeName() + ".csv";
  FileDialog::getSaveFileName("Export stream to CSV file", dir, ".csv", bindSource(can, [](const std::string &fn) {
    if (!fn.empty()) {
      utils::exportToCSV(fn);
    }
  }));
}

void MainWindow::newFile(SourceSet s) {
  closeFile(s, bindSource(can, [s]() { dbc()->open(s, std::string(""), std::string("")); }));
}

void MainWindow::openFile(SourceSet s) {
  remindSaveChanges(bindSource(can, [this, s]() {
    FileDialog::getOpenFileName("Open File", settings.last_dir, ".dbc", bindSource(can, [this, s](const std::string &fn) {
      if (!fn.empty()) {
        loadFile(fn, s);
      }
    }));
  }));
}

void MainWindow::loadFile(const std::string &fn, SourceSet s, std::function<void()> then) {
  if (then) then = bindSource(can, std::move(then));
  if (!fn.empty()) {
    closeFile(s, bindSource(can, [this, fn, s, then]() {
      std::string error;
      if (dbc()->open(s, fn, &error)) {
        updateRecentFiles(fn);
        showStatusMessage("DBC file " + fn + " loaded", 2000);
        if (then) then();
      } else {
        MessageBox::warning("Failed to load DBC file", "Failed to parse DBC file " + fn, error, then);
      }
    }));
  } else if (then) {
    then();
  }
}

void MainWindow::loadDBCFromOpendbc(const std::string &name) {
  loadFile(std::string(OPENDBC_FILE_PATH) + "/" + name);
}

void MainWindow::loadFromClipboard(SourceSet s, bool close_all) {
  std::string text;
  if (!utils::getClipboardText(&text)) {
    MessageBox::warning("Load from Clipboard", "No clipboard tool found. Install xclip (X11) or wl-clipboard (Wayland).");
    return;
  }
  if (text.empty()) {
    MessageBox::warning("Load from Clipboard", "Clipboard is empty.");
    return;
  }

  closeFile(s, bindSource(can, [s, text]() {
    std::string error;
    bool ret = dbc()->open(s, std::string(""), text, &error);
    if (ret && dbc()->nonEmptyDBCCount() > 0) {
      MessageBox::information("Load from Clipboard", "DBC loaded successfully.");
    } else {
      MessageBox::warning("Failed to load DBC from clipboard", "Make sure the clipboard contains correctly formatted DBC text.", error);
    }
  }));
}

MainWindow::~MainWindow() {
  installDownloadProgressHandler(nullptr);
  installMessageHandler(nullptr);
  *alive_ = false;
  releaseStream();
  can = nullptr;
}

// the tool dialogs are connected into the messages widget, and the video widget's RouteInfoDlg keeps a raw
// pointer to the replay, so the dialogs go first and the widgets before the stream; the stream's destructor
// joins the threads that read the global `can`
void MainWindow::releaseStream() {
  camera_panes_.clear();
  charts_widget_.reset();
  for (auto &view : source_views_) {
    SourceScope scope(view->stream.get());
    view->tools.clear();
    view->connections.clear();
    view->inspector.clear();
    view->messages.reset();
    unregisterSource(view->stream.get());
  }
  can = &dummy_;
  source_views_.clear();
}

void MainWindow::openStream(std::unique_ptr<AbstractStream> stream, const std::string &dbc_file) {
  if (!dynamic_cast<DummyStream *>(stream.get())) {
    for (const auto &view : source_views_) {
      auto *existing = view->stream.get();
      if (typeid(*existing) != typeid(*stream) || existing->routeName() != stream->routeName()) continue;
      const auto id = existing->source_id;
      const auto slot = std::exchange(source_to_replace_, {});
      if (!slot.empty() && slot != id) mergeSourceSlot(slot, id);
      selectSource(id);
      showStatusMessage("Source already open", 2000);
      return;
    }
  }
  if (stream->liveStreaming() && !dynamic_cast<DummyStream *>(stream.get())) {
    for (const auto &view : source_views_) if (view->stream->liveStreaming() && !dynamic_cast<DummyStream *>(view->stream.get())) {
      MessageBox::information("Live source", "Close the current live source before adding another live connection.");
      return;
    }
  }
  startStream(std::move(stream), dbc_file);
}

void MainWindow::startStream(std::unique_ptr<AbstractStream> stream, const std::string &dbc_file) {
  std::string id = source_to_replace_;
  source_to_replace_.clear();
  if (id.empty() && dynamic_cast<DummyStream *>(sourceById(selected_source_))) id = selected_source_;
  if (id.empty()) for (const auto &view : source_views_) {
    if (dynamic_cast<DummyStream *>(view->stream.get())) { id = view->stream->source_id; break; }
  }
  SourceView *view = nullptr;
  for (auto &candidate : source_views_) if (candidate->stream->source_id == id) view = candidate.get();
  if (view) {
    SourceScope scope(view->stream.get());
    if (charts_widget_) charts_widget_->removeSource(id);
    camera_panes_.erase(std::remove_if(camera_panes_.begin(), camera_panes_.end(), [&](auto &p) { return p.source == id; }), camera_panes_.end());
    view->tools.clear();
    view->connections.clear();
    view->inspector.clear();
    view->messages.reset();
    unregisterSource(view->stream.get());
  } else {
    auto source = std::make_unique<SourceView>();
    view = source.get();
    source_views_.push_back(std::move(source));
    if (id.empty()) do { id = "source" + std::to_string(next_source_id_++); } while (sourceById(id));
  }
  ++source_load_generation_[id];
  can = &dummy_;
  stream->source_id = id;
  stream->source_label = dynamic_cast<DummyStream *>(stream.get()) ? "Source " + std::to_string(source_views_.size()) : stream->routeName();
  view->stream = std::move(stream);
  registerSource(view->stream.get());
  selected_source_ = id;
  can = view->stream.get();
  SourceScope scope(can);
  const std::string source_id = id;
  view->connections.push_back(dbc()->fileChanged.connect([this, source_id]() {
    withSource(source_id, [this]() { dbcFileChanged(); });
  }));
  view->connections.push_back(UndoStack::instance()->cleanChanged.connect([this, source_id](bool clean) {
    withSource(source_id, [this, clean]() { window_modified_ = !clean; updateWindowTitle(); });
  }));
  view->connections.push_back(can->error.connect([](const std::string &message) { MessageBox::warning("Source", message); }));
  createDockWidgets();
  view->connections.push_back(can->eventsMerged.connect([this, source_id](const MessageEventsMap &) {
    withSource(source_id, [this]() { eventsMerged(); });
  }));
  if (!dbc_file.empty()) loadFile(dbc_file);
  if (!dbc()->dbcCount()) dbc()->open(SOURCE_ALL, std::string(), std::string());
  can->start();
  if (default_workspace_) makeDefaultWidgets();
  timeline_.setSources(orderedSources());
  timeline_.selectSource(id);
  updateWindowTitle();
  nextFrame([this]() { restoreSessionState(); });
}

void MainWindow::eventsMerged() {
  const std::string fingerprint = can->carFingerprint();
  if (!can->liveStreaming() && std::exchange(currentSource().fingerprint, fingerprint) != fingerprint) {
    // Don't overwrite already loaded DBC
    auto it = fingerprint_to_dbc_.find(currentSource().fingerprint);
    if (!dbc()->nonEmptyDBCCount() && it != fingerprint_to_dbc_.end()) {
      nextFrame([this, dbc_name = it->second]() { loadDBCFromOpendbc(dbc_name + ".dbc"); });
    }
  }
}

void MainWindow::saveFiles(bool as, std::function<void()> then) {
  const std::vector<DBCFile *> files = dbc()->nonEmptyDBCFiles();
  auto next = std::make_shared<std::function<void(size_t)>>();
  std::weak_ptr<std::function<void(size_t)>> weak_next = next;
  *next = bindSource(can, [this, as, files, weak_next, then](size_t i) {
    if (i >= files.size()) {
      if (then) then();
      return;
    }
    auto continuation = weak_next.lock();
    if (!continuation) return;
    auto cb = [continuation, i]() { (*continuation)(i + 1); };
    // A pending dialog can outlive a DBC replacement on the same source.
    if (!dbc()->allDBCFiles().count(files[i])) {
      cb();
      return;
    }
    as ? saveFileAs(files[i], cb) : saveFile(files[i], cb);
  });
  (*next)(0);
}

void MainWindow::save(std::function<void()> then) {
  saveFiles(false, std::move(then));
}

void MainWindow::saveAs(std::function<void()> then) {
  saveFiles(true, std::move(then));
}

void MainWindow::closeFile(SourceSet s, std::function<void()> then) {
  remindSaveChanges(bindSource(can, [s, then]() {
    if (s == SOURCE_ALL) {
      dbc()->closeAll();
    } else {
      dbc()->close(s);
    }
    if (then) then();
  }));
}

void MainWindow::closeFile(DBCFile *dbc_file) {
  assert(dbc_file != nullptr);
  remindSaveChanges(bindSource(can, [this, dbc_file]() {
    if (!dbc()->allDBCFiles().count(dbc_file)) return;
    dbc()->close(dbc_file);
    // Ensure we always have at least one file open
    if (dbc()->dbcCount() == 0) {
      newFile();
    }
  }));
}

void MainWindow::saveFile(DBCFile *dbc_file, std::function<void()> then) {
  assert(dbc_file != nullptr);
  if (!dbc_file->filename.empty()) {
    dbc_file->save();
    UndoStack::instance()->setClean();
    showStatusMessage("File saved", 2000);
    if (then) then();
  } else if (!dbc_file->isEmpty()) {
    saveFileAs(dbc_file, then);
  } else if (then) {
    then();
  }
}

void MainWindow::saveFileAs(DBCFile *dbc_file, std::function<void()> then) {
  std::string title = "Save File (bus: " + toString(dbc()->sources(dbc_file)) + ")";
  std::string default_path = (std::filesystem::path(settings.last_dir) / "untitled.dbc").string();
  FileDialog::getSaveFileName(title, default_path, ".dbc", bindSource(can, [this, dbc_file, then](const std::string &fn) {
    if (!dbc()->allDBCFiles().count(dbc_file)) return;
    if (!fn.empty()) {
      dbc_file->saveAs(fn);
      UndoStack::instance()->setClean();
      showStatusMessage("File saved as " + fn, 2000);
      updateRecentFiles(fn);
    }
    if (then) then();
  }));
}

void MainWindow::saveToClipboard() {
  // Should not be called with more than 1 file open
  for (auto dbc_file : dbc()->nonEmptyDBCFiles()) {
    saveFileToClipboard(dbc_file);
  }
}

void MainWindow::saveFileToClipboard(DBCFile *dbc_file) {
  assert(dbc_file != nullptr);
  copyToClipboard(dbc_file->generateDBC());
}

void MainWindow::copyToClipboard(const std::string &text) {
  if (utils::setClipboardText(text)) {
    MessageBox::information("Copy to Clipboard", "DBC copied successfully.");
  } else {
    MessageBox::warning("Copy to Clipboard", "Failed to copy DBC to clipboard. Install xclip (X11) or wl-clipboard (Wayland).");
  }
}

void MainWindow::drawManageDBCsMenu() {
  for (int source : can->sources) {
    if (source >= 64) continue; // Sent and blocked buses are handled implicitly

    SourceSet ss = {source, uint8_t(source + 128), uint8_t(source + 192)};

    auto dbc_file = dbc()->findDBCFile(source);
    const std::string title = "Bus " + std::to_string(source) + " (" + (dbc_file ? dbc_file->name() : "No DBCs loaded") + ")";
    ImGui::PushID(source);
    if (dropdown::BeginMenu(title.c_str())) {
      if (dropdown::Item("New DBC File")) newFile(ss);
      if (dropdown::Item("Open DBC File...")) openFile(ss);
      if (dropdown::Item("Load DBC from Clipboard")) loadFromClipboard(ss, false);

      // Show sub-menu for each dbc for this source.
      if (dbc_file) {
        ImGui::Separator();
        dropdown::Item((dbc_file->name() + " (" + toString(dbc()->sources(dbc_file)) + ")").c_str(), nullptr, false, false);
        if (dropdown::Item("Save...")) saveFile(dbc_file);
        if (dropdown::Item("Save As...")) saveFileAs(dbc_file);
        if (dropdown::Item("Copy to Clipboard")) saveFileToClipboard(dbc_file);
        if (dropdown::Item("Remove from This Bus...")) closeFile(ss, {});
        if (dropdown::Item("Remove from All Buses...")) closeFile(dbc_file);
      }
      dropdown::EndMenu();
    }
    ImGui::PopID();
  }
}

void MainWindow::updateRecentFiles(const std::string &fn) {
  settings.recent_files.erase(std::remove(settings.recent_files.begin(), settings.recent_files.end(), fn), settings.recent_files.end());
  settings.recent_files.insert(settings.recent_files.begin(), fn);
  while (settings.recent_files.size() > MAX_RECENT_FILES) {
    settings.recent_files.pop_back();
  }
  settings.last_dir = std::filesystem::absolute(fn).parent_path().string();
}

void MainWindow::drawRecentFilesMenu() {
  int num_recent_files = std::min<int>(settings.recent_files.size(), MAX_RECENT_FILES);
  if (!num_recent_files) {
    dropdown::Item("No Recent Files", nullptr, false, false);
    return;
  }

  for (int i = 0; i < num_recent_files; ++i) {
    std::string text = std::to_string(i + 1) + " " + std::filesystem::path(settings.recent_files[i]).filename().string();
    ImGui::PushID(i);
    if (dropdown::Item(text.c_str())) loadFile(settings.recent_files[i]);
    ImGui::PopID();
  }
}

void MainWindow::remindSaveChanges(std::function<void()> then) {
  if (then) then = bindSource(can, std::move(then));
  if (UndoStack::instance()->isClean()) {
    UndoStack::instance()->clear();
    if (then) then();
    return;
  }
  std::string text = "You have unsaved changes. Select OK to save them or Cancel to discard them.";
  MessageBox::question("Unsaved Changes", text, bindSource(can, [this, then](bool ok) {
    if (ok) {
      save(bindSource(can, [this, then]() { remindSaveChanges(then); }));
    } else {
      UndoStack::instance()->clear();
      if (then) then();
    }
  }));
}

void MainWindow::updateDownloadProgress(uint64_t cur, uint64_t total, bool success) {
  const double fraction = total > 0 ? cur / (double)total : 0.0;
  if (wait_dlg_.open) wait_dlg_.value = (int)(fraction * 100);
  if (success && cur < total) {
    status_bar_.progress_value = fraction;
    status_bar_.progress_text = "Downloading " + std::to_string((int)(fraction * 100)) + "% (" + formattedDataSize(total) + ")";
    status_bar_.progress_visible = true;
  } else {
    status_bar_.progress_visible = false;
  }
}

void MainWindow::close() {
  if (closing_) return;
  closing_ = true;
  auto pending = std::make_shared<std::vector<std::string>>();
  for (const auto &source : source_views_) pending->push_back(source->stream->source_id);
  auto step = std::make_shared<std::function<void()>>();
  const std::weak_ptr<std::function<void()>> weak_step = step;
  *step = [this, pending, weak_step]() {
    if (pending->empty()) { finishClose(); return; }
    auto next = weak_step.lock();
    const auto id = pending->back(); pending->pop_back();
    withSource(id, [this, next]() { remindSaveChanges([next]() { (*next)(); }); });
  };
  (*step)();
}

void MainWindow::finishClose() {
  // save states
  auto &state = inistate::main_window;
  state.maximized = glfwGetWindowAttrib(window_, GLFW_MAXIMIZED);
  if (full_screen_) {
#ifndef __APPLE__
    // macOS full screen is the native Cocoa toggle, keep the loaded geometry there
    state.pos[0] = windowed_rect_[0]; state.pos[1] = windowed_rect_[1];
    state.size[0] = windowed_rect_[2]; state.size[1] = windowed_rect_[3];
#endif
  } else if (!state.maximized) {
    glfwGetWindowPos(window_, &state.pos[0], &state.pos[1]);
    glfwGetWindowSize(window_, &state.size[0], &state.size[1]);
  }
  state.has_geometry = state.size[0] > 0 && state.size[1] > 0;
  state.workspace_version = 4;
  state.log_messages_visible = currentSource().logs_visible;
  state.charts_visible = charts_visible_;
  state.details_visible = currentSource().inspector_visible;
  state.messages_visible = currentSource().messages_visible;
  state.video_visible = !camera_panes_.empty();
  state.playback_visible = playback_visible_;
  settings.ui_state = inistate::save();

  saveSessionState();
  settings.save();
  exited_ = true;
}

void MainWindow::openSettings() {
  settings_dialog_.open();
}

void MainWindow::findSimilarBits() {
  auto dlg = std::make_unique<FindSimilarBitsDlg>();
  dlg->connections_.push_back(dlg->openMessage.connect([this](const MessageId &id) { currentSource().messages->selectMessage(id); }));
  currentSource().tools.push_back(std::move(dlg));
}

void MainWindow::findSignal() {
  auto dlg = std::make_unique<FindSignalDlg>();
  dlg->connections_.push_back(dlg->openMessage.connect([this](const MessageId &id) { currentSource().messages->selectMessage(id); }));
  currentSource().tools.push_back(std::move(dlg));
}

void MainWindow::toggleHelp() {
  help_overlay_.toggle();
}

void MainWindow::toggleFullScreen() {
#ifdef __APPLE__
  toggleNativeFullScreen(window_);
#else
  full_screen_ = !full_screen_;
  if (full_screen_) {
    glfwGetWindowPos(window_, &windowed_rect_[0], &windowed_rect_[1]);
    glfwGetWindowSize(window_, &windowed_rect_[2], &windowed_rect_[3]);
    GLFWmonitor *monitor = glfwGetPrimaryMonitor();
    const GLFWvidmode *mode = glfwGetVideoMode(monitor);
    glfwSetWindowMonitor(window_, monitor, 0, 0, mode->width, mode->height, mode->refreshRate);
  } else {
    glfwSetWindowMonitor(window_, nullptr, windowed_rect_[0], windowed_rect_[1], windowed_rect_[2], windowed_rect_[3], 0);
    glfwMaximizeWindow(window_);
  }
#endif
}

void MainWindow::saveSessionState() {
  captureWorkspace();
  persistWorkspaces();
  settings.recent_dbc_file = "";
  settings.active_msg_id = "";
  settings.selected_msg_ids.clear();

  const auto files = dbc()->nonEmptyDBCFiles();
  if (!files.empty()) settings.recent_dbc_file = files.front()->filename;

  if (auto *detail = currentSource().inspector.getDetailWidget()) {
    auto [active_id, ids] = detail->serializeMessageIds();
    settings.active_msg_id = active_id;
    settings.selected_msg_ids = ids;
  }
}

void MainWindow::restoreSessionState() {
  if (!charts_widget_) return;
  if (!pending_workspace_layout_.empty()) {
    if (charts_widget_->restoreLayout(pending_workspace_layout_, true) == ChartsWidget::LayoutStatus::Restored)
      pending_workspace_layout_.clear();
  }
  // CAN layouts may need the DBC loaded by eventsMerged(). dbcFileChanged() retries while definitions are missing.
  if (!startup_layout_.empty()) {
    if (charts_widget_->openLayout(startup_layout_, true) != ChartsWidget::LayoutStatus::MissingCan) {
      startup_layout_.clear();
      pending_workspace_layout_.clear();
    }
  }
  if (dynamic_cast<DummyStream *>(can) || dbc()->nonEmptyDBCCount() == 0) return;
  auto pending = pending_workspace_inspectors_.find(can->source_id);
  if (pending == pending_workspace_inspectors_.end()) return;
  std::vector<std::string> ids;
  for (const auto &id : pending->second["messages"].array_items()) ids.push_back(id.string_value());
  // DBC file changes can arrive separately. Keep unresolved tabs pending until
  // every saved message has a definition, including messages on other buses.
  if (!std::all_of(ids.begin(), ids.end(), [](const auto &id) { return dbc()->msg(MessageId::fromString(id)) != nullptr; })) return;
  const auto active = pending->second["active"].string_value();
  if (!active.empty() && !dbc()->msg(MessageId::fromString(active))) return;
  if (!ids.empty()) currentSource().inspector.ensureDetailWidget()->restoreTabs(active, ids);
  pending_workspace_inspectors_.erase(pending);
}

void MainWindow::handleShortcuts() {
  timeline_.handleShortcuts();
  const ImGuiIO &io = ImGui::GetIO();
  for (const KeyEvent &e : takeKeyEvents()) {
    const bool ctrl = e.mods & (GLFW_MOD_CONTROL | GLFW_MOD_SUPER);
    const bool shift = e.mods & GLFW_MOD_SHIFT;
    // a focused text input consumes Space but not the Ctrl/F-key sequences

    if (e.key == GLFW_KEY_F1) toggleHelp();
    if (e.key == GLFW_KEY_F11 && ctrl) toggleFullScreen();
    // an open popup or a focused text input takes Esc first
    if (e.key == GLFW_KEY_ESCAPE && full_screen_ && !io.WantTextInput &&
        !ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
      toggleFullScreen();
    }
    if (!ctrl) continue;
    if (e.key == GLFW_KEY_N) newFile();
    if (e.key == GLFW_KEY_O) openFile();
    if (e.key == GLFW_KEY_S) {
      if (shift) {
        if (dbc()->nonEmptyDBCCount() == 1) saveAs();
      } else if (dbc()->nonEmptyDBCCount() > 0) {
        save();
      }
    }
    // a focused text input swallows Ctrl+Z / Ctrl+Shift+Z
    if (e.key == GLFW_KEY_Z && !io.WantTextInput) shift ? UndoStack::instance()->redo() : UndoStack::instance()->undo();
    if (e.key == GLFW_KEY_Q) close();
  }
}

void MainWindow::drawPanelToggles() {
  ImGui::SameLine();
  if (dropdown::BeginMenu("Add widget")) {
    drawAddWidgetMenu();
    dropdown::EndMenu();
  }
}

void MainWindow::drawPlaybackBar() {
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
  ImGui::BeginChild("playback_bar", ImVec2(0, timeline_.height()), ImGuiChildFlags_AlwaysUseWindowPadding,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  ImGui::PopStyleVar();
  const bool loaded = std::any_of(source_views_.begin(), source_views_.end(), [](const auto &view) {
    return !dynamic_cast<DummyStream *>(view->stream.get());
  });
  const auto &saved_sources = workspaces_.empty() ? json11::Json::array{} : workspaces_[active_workspace_]["sources"].array_items();
  const bool has_references = std::any_of(saved_sources.begin(), saved_sources.end(), [](const auto &source) {
    return !source["route"].string_value().empty();
  });
  if (!loaded && has_references) {
    if (iconTextButton("open_saved_routes", icon::PLUS_LG, "Open saved routes")) openWorkspaceRoutes(workspaces_[active_workspace_]);
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Load this workspace's referenced data");
  } else timeline_.draw();
  ImGui::EndChild();
}

void MainWindow::drawStatusBar() {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyle().Colors[ImGuiCol_MenuBarBg]);
  ImGui::BeginChild("status_bar", ImVec2(0, ImGui::GetFrameHeight()), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
  const ImVec2 min = ImGui::GetWindowPos();
  ImGui::GetWindowDrawList()->AddRectFilled(min, ImVec2(min.x + ImGui::GetWindowWidth(), min.y + 1.0f), ImGui::GetColorU32(ImGuiCol_Border));
  // a borderless child gets no WindowPadding, so both ends sit flush against the edge and clip. Inset by
  // WindowPadding.x, which lines the text up with the content of the docked panels above (the messages table).
  const float width = ImGui::GetContentRegionAvail().x;
  const float pad = ImGui::GetStyle().WindowPadding.x;
  pushMonoFont(ImGui::GetStyle().FontSizeBase);
  const float fps_x = std::max(pad, width - pad - ImGui::CalcTextSize("999 FPS").x);
  popMonoFont();
  const float progress_width = std::min(300.0f, std::max(0.0f, fps_x - pad - 20.0f));
  const float progress_x = fps_x - progress_width - 10.0f;
  const float message_end = status_bar_.progress_visible ? progress_x - ImGui::GetStyle().ItemSpacing.x : fps_x - 10.0f;
  ImGui::PushClipRect(min, ImVec2(min.x + std::max(pad, message_end), min.y + ImGui::GetWindowHeight()), true);
  ImGui::SetCursorPosX(pad);
  ImGui::AlignTextToFramePadding();
  const float text_y = ImGui::GetCursorPosY();
  // a temporary message hides the normal widgets, permanent widgets stay on the right
  auto &bar = status_bar_;
  if (!bar.message.empty() && (bar.message_until == 0 || ImGui::GetTime() < bar.message_until)) {
    ImGui::TextUnformatted(bar.message.c_str());
  } else {
    bar.message.clear();
    ImGui::TextUnformatted("For help, press F1");
  }
  ImGui::PopClipRect();
  if (bar.progress_visible && progress_width > 0) {
    const float progress_height = 16.0f;
    ImGui::PushFont(ImGui::GetFont(), 12.0f);
    const std::string percentage = std::to_string((int)(bar.progress_value * 100)) + "%";
    const char *label = bar.progress_text.c_str();
    const float text_width = progress_width - 2 * ImGui::GetStyle().FramePadding.x;
    if (ImGui::CalcTextSize(label).x > text_width) label = percentage.c_str();
    if (ImGui::CalcTextSize(label).x > text_width) label = "";
    ImGui::SameLine(progress_x);
    ImGui::SetCursorPosY((ImGui::GetWindowHeight() - progress_height) / 2.0f);
    ImGui::ProgressBar(bar.progress_value, ImVec2(progress_width, progress_height), label);
    ImGui::PopFont();
    ImGui::SetItemTooltip("%s", bar.progress_text.c_str());
  }
  ImGui::SameLine(fps_x);
  ImGui::SetCursorPosY(text_y);
  pushMonoFont(ImGui::GetStyle().FontSizeBase);
  ImGui::Text("%3.0f FPS", ImGui::GetIO().Framerate);
  popMonoFont();
  ImGui::SetItemTooltip("UI rendering rate (frames per second)");
  ImGui::EndChild();
  ImGui::PopStyleColor();
}

void MainWindow::drawWaitDialog() {
  const char *id = "###WaitDialog";
  if (wait_dlg_.open && !ImGui::IsPopupOpen(id) && ImGui::GetTime() >= wait_dlg_.show_at) ImGui::OpenPopup(id);
  if (!ImGui::IsPopupOpen(id)) return;  // keep submitting until CloseCurrentPopup ran, a stale modal blocks all input
  ImGui::SetNextWindowSize(ImVec2(400.0f, 0.0f), ImGuiCond_Always);
  setNextDialogWindow(ImVec2(0.0f, 0.0f));
  if (ImGui::BeginPopupModal(id, nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted(wait_dlg_.text.c_str());
    // no text until the progress is set
    ImGui::ProgressBar(wait_dlg_.value / 100.0f, ImVec2(-1.0f, 0.0f), wait_dlg_.value == 0 ? "" : (const char *)nullptr);
    bool abort = false, rejected = false;
    dialogButtons("Abort", &abort, &rejected, true, nullptr);
    if (abort || rejected) {
      wait_dlg_.open = false;
      close();
    }
    if (!wait_dlg_.open) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
  }
}

void MainWindow::drawDockspace() {
  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  // Use the menu bar's current-frame reservation, including on the first frame.
  const ImRect work_rect = static_cast<const ImGuiViewportP *>(viewport)->GetBuildWorkRect();
  ImGui::SetNextWindowPos(work_rect.Min);
  ImGui::SetNextWindowSize(work_rect.GetSize());
  ImGui::SetNextWindowViewport(viewport->ID);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
  const ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
                                 ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground |
                                 ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
  ImGui::Begin("##host", nullptr, flags);
  ImGui::PopStyleVar(3);

  // the status bar sits below the dockspace: reserve its height plus the item spacing between the two,
  // otherwise the host window is a few pixels taller than the viewport and scrolls
  const float status_height = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y;
  const float playback_height = playback_visible_ ? timeline_.height() + ImGui::GetStyle().ItemSpacing.y : 0.0f;
  const ImVec2 dock_size(ImGui::GetContentRegionAvail().x, std::max(1.0f, ImGui::GetContentRegionAvail().y - status_height - playback_height));
  const ImGuiID dock_id = ImGui::GetID("cabana_dockspace");
  if (reset_layout_ || ImGui::DockBuilderGetNode(dock_id) == nullptr) {
    // Sources left, synchronized views in the center, optional CAN inspection right.
    ImGui::DockBuilderRemoveNode(dock_id);
    ImGui::DockBuilderAddNode(dock_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodePos(dock_id, ImGui::GetCursorScreenPos());
    ImGui::DockBuilderSetNodeSize(dock_id, dock_size);
    ImGuiID views = dock_id, sources = 0, video = 0, details = 0;
    ImGui::DockBuilderSplitNode(views, ImGuiDir_Left, 0.23f, &sources, &views);
    ImGui::DockBuilderSplitNode(views, ImGuiDir_Right, 0.34f, &details, &views);
    ImGui::DockBuilderSplitNode(views, ImGuiDir_Up, 0.42f, &video, &views);
    for (const auto &source : source_views_) {
      SourceScope scope(source->stream.get());
      if (source->messages_visible) ImGui::DockBuilderDockWindow(panelName("can").c_str(), sources);
      if (source->logs_visible) ImGui::DockBuilderDockWindow(panelName("logs").c_str(), sources);
      if (source->inspector_visible) ImGui::DockBuilderDockWindow(panelName("inspector").c_str(), details);
    }
    for (const auto &camera : camera_panes_) {
      const std::string name = "###camera_" + camera.id;
      ImGui::DockBuilderDockWindow(name.c_str(), video);
    }
    if (charts_widget_) for (const auto &name : charts_widget_->windowNames()) ImGui::DockBuilderDockWindow(name.c_str(), views);
    ImGui::DockBuilderGetNode(views)->LocalFlags &= ~ImGuiDockNodeFlags_CentralNode;
    ImGui::DockBuilderFinish(dock_id);
    setDefaultPanelDock(views);
    reset_layout_ = false;
  }
  // Panels can shrink below the full signals toolbar width; extra controls go into overflow menus.
  const float min_panel_width = (SignalView::minimumWidth() + (ImGui::GetStyle().WindowPadding.x + ImGui::GetStyle().WindowBorderSize) * 2) * 0.5f;
  ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(min_panel_width, ImGui::GetStyle().WindowMinSize.y));
  const ImVec2 dock_origin = ImGui::GetCursorScreenPos();
  scrollableDockSpace(dock_id, dock_size);
  // Resolve the insertion point from restored docking too, not only a freshly built layout.
  ImGuiID insertion_dock = 0;
  if (charts_widget_) for (const auto &name : charts_widget_->windowNames()) {
    if (auto *window = ImGui::FindWindowByName(name.c_str()); window && window->DockNode) {
      insertion_dock = window->DockNode->ID;
      break;
    }
  }
  if (!insertion_dock) {
    float largest_area = -1;
    std::function<void(ImGuiDockNode *)> find_leaf = [&](ImGuiDockNode *node) {
      if (!node) return;
      if (node->IsLeafNode()) {
        const float area = node->Size.x * node->Size.y;
        if (area > largest_area) { largest_area = area; insertion_dock = node->ID; }
      } else { find_leaf(node->ChildNodes[0]); find_leaf(node->ChildNodes[1]); }
    };
    find_leaf(ImGui::DockBuilderGetNode(dock_id));
  }
  setDefaultPanelDock(insertion_dock);
  const bool empty = camera_panes_.empty() && (!charts_widget_ || charts_widget_->chartCount() == 0) &&
    std::none_of(source_views_.begin(), source_views_.end(), [](const auto &v) { return v->messages_visible || v->logs_visible || v->inspector_visible; });
  if (empty) {
    const float width = std::min(420.0f, dock_size.x - 32);
    ImGui::SetCursorScreenPos(ImVec2(dock_origin.x + std::max(16.0f, (dock_size.x - width) * .5f), dock_origin.y + std::max(16.0f, dock_size.y * .35f)));
    ImGui::BeginChild("workspace_welcome", ImVec2(width, 140), ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
    pushBoldFont(); ImGui::TextUnformatted("Your workspace"); popBoldFont();
    ImGui::TextWrapped("Add a chart, camera, or message browser. Drag tabs to arrange your workspace.");
    ImGui::Spacing();
    if (iconTextButton("welcome_source", icon::PLUS_LG, "Add source")) selectAndOpenStream();
    ImGui::SameLine();
    if (iconTextButton("welcome_widget", icon::PLUS_LG, "Add widget")) ImGui::OpenPopup("welcome_widgets");
    if (dropdown::BeginPopup("welcome_widgets")) { drawAddWidgetMenu(); dropdown::EndPopup(); }
    ImGui::EndChild();
    ImGui::SetCursorScreenPos(ImVec2(dock_origin.x, dock_origin.y + dock_size.y + ImGui::GetStyle().ItemSpacing.y));
  }
  ImGui::PopStyleVar();
  if (playback_visible_) drawPlaybackBar();
  drawStatusBar();
  ImGui::End();
}

namespace {
// Every workspace panel uses the same docking and floating behavior. Keep the title
// strip visible so moving and closing a panel are always available.
void setNextPanelClass() {
  ImGuiWindowClass window_class;
  window_class.ViewportFlagsOverrideSet = ImGuiViewportFlags_NoAutoMerge;
  window_class.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoWindowMenuButton;
  ImGui::SetNextWindowClass(&window_class);
}

bool beginPanel(const char *name, bool *open, ImGuiWindowFlags flags = 0) {
  return beginDockablePanel(name, open, flags);
}
}  // namespace

void MainWindow::showMessage(const MessageId &id) {
  currentSource().inspector.setMessage(id);
  currentSource().inspector_visible = true;
  selectPanelTab(panelName("inspector").c_str());
}

void MainWindow::selectPanelTab(const char *name) {
  // Select a docked panel after it has been submitted, without stealing keyboard
  // focus from the message list (which needs to keep handling the arrow keys).
  nextFrame([name = std::string(name)]() {
    if (auto *window = ImGui::FindWindowByName(name.c_str()); window && window->DockNode && window->DockNode->TabBar) {
      window->DockNode->TabBar->NextSelectedTabId = window->TabId;
    }
  });
}

void MainWindow::drawMessagesPanel() {
  const std::string name = panelName("can");
  setNextPanelClass();
  if (beginPanel(name.c_str(), &currentSource().messages_visible) && currentSource().messages) {
    help_overlay_.add(currentSource().messages->whatsThis(), ImGui::GetCurrentWindow()->Rect());
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextDisabled("%s", currentSource().messages->title().c_str());
    ImGui::PopTextWrapPos();
    if ((ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) || ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) && ImGui::IsMouseClicked(0)) selectSource(can->source_id);
    currentSource().messages->draw();
  }
  ImGui::End();
}

void MainWindow::drawLogMessagesPanel() {
  setNextPanelClass();
  if (beginPanel(panelName("logs").c_str(), &currentSource().logs_visible) && charts_widget_) {
    help_overlay_.add("<b>openpilot Messages</b><br />Search to filter messages and fields.<br />"
                      "Double-click a field to create a chart.<br />Drag a field onto a chart to compare.",
                      ImGui::GetCurrentWindow()->Rect());
    if ((ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) || ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) && ImGui::IsMouseClicked(0)) selectSource(can->source_id);
    charts_widget_->drawSignalBrowser();
  }
  ImGui::End();
}

void MainWindow::drawChartsPanel() {
  if (charts_widget_) charts_widget_->draw();
}

void MainWindow::drawVideoPanel() {
  for (auto &camera : camera_panes_) {
    auto *source = sourceById(camera.source);
    if (!source || !camera.widget) continue;
    SourceScope scope(source);
    const std::string name = std::string(VideoWidget::cameraName(camera.type)) + " · " + source->source_label + "###camera_" + camera.id;
    setNextPanelClass();
    const bool visible = beginPanel(name.c_str(), &camera.visible, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    camera.widget->setVisible(visible && camera.visible);
    if (visible) {
      if ((ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) || ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) && ImGui::IsMouseClicked(0)) {
        selected_source_ = source->source_id;
        timeline_.selectSource(source->source_id, camera.type);
      }
      camera.widget->drawVideo();
    }
    ImGui::End();
  }
  camera_panes_.erase(std::remove_if(camera_panes_.begin(), camera_panes_.end(), [](const auto &camera) { return !camera.visible; }), camera_panes_.end());
}

void MainWindow::drawDetailsPanel() {
  setNextPanelClass();
  auto *detail = currentSource().inspector.getDetailWidget();
  const std::string title = panelName("inspector");
  if (beginPanel(title.c_str(), &currentSource().inspector_visible, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
    if (detail) {
      currentSource().inspector.draw();
    } else {
      const auto &style = ImGui::GetStyle();
      const ImVec2 origin = ImGui::GetCursorScreenPos();
      const ImVec2 avail = ImGui::GetContentRegionAvail();
      const float padding = style.WindowPadding.x * 2;
      const float text_width = std::max(1.0f, std::min(avail.x - padding * 2, ImGui::GetFontSize() * 32));
      const char *heading = "No CAN message selected";
      const char *description = "Select a CAN message to inspect its bits, signals, and history.";
      pushBoldFont();
      const ImVec2 heading_size = ImGui::CalcTextSize(heading, nullptr, false, text_width);
      popBoldFont();
      const ImVec2 description_size = ImGui::CalcTextSize(description, nullptr, false, text_width);
      const float height = heading_size.y + description_size.y + ImGui::GetFrameHeight() + style.ItemSpacing.y * 2;
      float y = origin.y + std::max(padding, (avail.y - height) * 0.5f);
      auto text = [&](const char *value, const ImVec2 &size) {
        ImGui::SetCursorScreenPos(ImVec2(origin.x + std::max(0.0f, (avail.x - size.x) * 0.5f), y));
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + text_width);
        ImGui::TextUnformatted(value);
        ImGui::PopTextWrapPos();
        y += size.y + style.ItemSpacing.y;
      };
      pushBoldFont();
      text(heading, heading_size);
      popBoldFont();
      text(description, description_size);
      const float button_width = ImGui::CalcTextSize("Browse CAN").x + style.FramePadding.x * 2;
      ImGui::SetCursorScreenPos(ImVec2(origin.x + std::max(0.0f, (avail.x - button_width) * 0.5f), y));
      if (ImGui::Button("Browse CAN")) {
        currentSource().messages_visible = true;
        selectPanelTab(panelName("can").c_str());
      }
    }
    if (detail && help_overlay_.visible()) {
      for (const auto &[text, rect] : detail->helpRects()) help_overlay_.add(text, rect);
    }
  }
  ImGui::End();
}

void MainWindow::draw() {
#ifdef __APPLE__
  full_screen_ = isNativeFullScreen(window_);
#endif
  auto pending = std::move(next_frame_);
  next_frame_.clear();
  for (auto &fn : pending) fn();

  if (auto *selected = sourceById(selected_source_)) can = selected;
  timeline_.setSources(orderedSources());
  timeline_.tick();
  if (ImGui::GetTopMostPopupModal() == nullptr) {
    handleShortcuts();
  } else {
    takeKeyEvents();  // modal dialogs swallow the shortcuts
  }
  if (!full_screen_) drawMenuBar();
  drawDockspace();
  if (auto *selected = sourceById(timeline_.selectedSource())) {
    selected_source_ = selected->source_id;
    can = selected;
  }

  for (auto &source : source_views_) {
    SourceScope scope(source->stream.get());
    if (source->inspector_visible) drawDetailsPanel();
    if (source->messages_visible) drawMessagesPanel();
    if (source->logs_visible) drawLogMessagesPanel();
    for (auto it = source->tools.begin(); it != source->tools.end();) it = (*it)->draw() ? it + 1 : source->tools.erase(it);
  }
  drawVideoPanel();
  drawChartsPanel();

  stream_selector_.draw();
  settings_dialog_.draw();
  drawWaitDialog();
  FileDialog::draw();
  MessageBox::draw();
  help_overlay_.draw();

  // Escape closes the top-most non-modal popup (a menu or a combo list) on its own; the modal dialogs
  // handled Escape themselves above when they were on top
  if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
    ImGuiWindow *top = topPopupWindow();
    if (top != nullptr && !(top->Flags & ImGuiWindowFlags_Modal)) ImGui::ClosePopupToLevel(GImGui->OpenPopupStack.Size - 1, true);
  }
}
