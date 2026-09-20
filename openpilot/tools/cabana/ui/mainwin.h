#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "tools/cabana/dbc/dbcmanager.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/ui/app.h"
#include "tools/cabana/core/source.h"
#include "tools/cabana/ui/timeline.h"
#include "tools/cabana/ui/dialogs/settingsdialog.h"
#include "tools/cabana/ui/dialogs/streamselector.h"
#include "tools/cabana/ui/helpoverlay.h"
#include "tools/cabana/ui/tools/tooldialog.h"
#include "tools/cabana/ui/chart/chartswidget.h"
#include "tools/cabana/ui/widgets/detailwidget.h"
#include "tools/cabana/ui/widgets/messageswidget.h"
#include "tools/cabana/ui/widgets/videowidget.h"

struct GLFWwindow;

class MainWindow {
public:
  MainWindow(GLFWwindow *window, std::unique_ptr<AbstractStream> stream, StreamLoader stream_loader, const std::string &dbc_file, const std::string &layout);
  ~MainWindow();
  void draw();
  void close();  // remind unsaved changes, save state, exit
  bool exited() const { return exited_; }
  void showStatusMessage(const std::string &msg, int timeout_ms = 0);
  void loadFile(const std::string &fn, SourceSet s = SOURCE_ALL, std::function<void()> then = {});

  void selectAndOpenStream();
  void openStream(std::unique_ptr<AbstractStream> stream, const std::string &dbc_file = {});
  void closeStream();
  void exportToCSV();

  void newFile(SourceSet s = SOURCE_ALL);
  void openFile(SourceSet s = SOURCE_ALL);
  void loadDBCFromOpendbc(const std::string &name);
  void save(std::function<void()> then = {});
  void saveAs(std::function<void()> then = {});
  void saveToClipboard();

private:
  bool hasStream() const { return dynamic_cast<const DummyStream *>(can) == nullptr; }
  void releaseStream();
  void startStream(std::unique_ptr<AbstractStream> stream, const std::string &dbc_file);
  void loadStartupStream(const std::string &dbc_file);
  void remindSaveChanges(std::function<void()> then);
  void closeFile(SourceSet s, std::function<void()> then);
  void closeFile(DBCFile *dbc_file);
  void saveFiles(bool as, std::function<void()> then);
  void saveFile(DBCFile *dbc_file, std::function<void()> then = {});
  void saveFileAs(DBCFile *dbc_file, std::function<void()> then = {});
  void saveFileToClipboard(DBCFile *dbc_file);
  void copyToClipboard(const std::string &text);
  void loadFingerprints();
  void loadFromClipboard(SourceSet s = SOURCE_ALL, bool close_all = true);
  void updateRecentFiles(const std::string &fn);
  void dbcFileChanged();
  void updateDownloadProgress(uint64_t cur, uint64_t total, bool success);
  void openSettings();
  void findSimilarBits();
  void findSignal();
  void toggleHelp();
  void toggleFullScreen();
  void updateWindowTitle();
  void eventsMerged();
  void initializeWorkspaces();
  void captureWorkspace();
  void persistWorkspaces();
  void switchWorkspace(int index, bool capture_current = true);
  void drawWorkspaceMenu();
  void importWorkspace(const std::string &path);
  json11::Json::array workspaces_;
  int active_workspace_ = 0;
  std::string pending_workspace_layout_;
  std::map<std::string, json11::Json> pending_workspace_inspectors_;

  void saveSessionState();
  void restoreSessionState();
  void finishClose();
  void nextFrame(std::function<void()> fn);
  void withSource(const std::string &id, std::function<void()> fn);
  void drawAddWidgetMenu();
  void drawSourcesMenu();
  void addCamera(const std::string &source, VisionStreamType type, bool crop = false, const std::string &id = {});
  void openWorkspaceRoutes(const json11::Json &document);
  void applyWorkspace(const json11::Json &document);
  void loadWorkspacePreset(const std::string &path);
  void removeSource(const std::string &id);
  void mergeSourceSlot(const std::string &old_id, const std::string &new_id);
  std::string sourceSlotRoute(const std::string &id) const;
  void bindSourceSlots(std::string id);
  void selectSource(const std::string &id);
  void makeDefaultWidgets();
  std::string panelName(const char *kind) const;
  struct SourceView {
    std::unique_ptr<AbstractStream> stream;
    std::unique_ptr<MessagesWidget> messages;
    CenterWidget inspector;
    bool messages_visible = false, logs_visible = false, inspector_visible = false;
    std::string fingerprint;
    std::vector<std::unique_ptr<ToolDialog>> tools;
    Connections connections;
  };
  SourceView &currentSource();
  std::vector<AbstractStream *> orderedSources() const;
  std::vector<std::unique_ptr<SourceView>> source_views_;
  std::string selected_source_;
  int next_source_id_ = 1;
  struct CameraPane {
    std::string id, source;
    VisionStreamType type;
    std::unique_ptr<VideoWidget> widget;
    bool visible = true;
  };
  std::vector<CameraPane> camera_panes_;
  int next_camera_id_ = 1;
  PlaybackTimeline timeline_;
  bool default_workspace_ = true;
  bool include_routes_ = false;
  std::string source_to_replace_;
  uint64_t workspace_generation_ = 0;
  std::unordered_map<std::string, uint64_t> source_load_generation_;
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
  void createDockWidgets();

  void handleShortcuts();
  void drawMenuBar();
  void drawFileMenu();
  void drawManageDBCsMenu();
  void drawRecentFilesMenu();
  void drawDockspace();
  void drawMessagesPanel();
  void drawLogMessagesPanel();
  void drawChartsPanel();
  void selectPanelTab(const char *name);
  void drawVideoPanel();
  void drawDetailsPanel();
  void showMessage(const MessageId &id);
  void drawPlaybackBar();
  void drawPanelToggles();
  void drawStatusBar();
  void drawWaitDialog();

  std::string startup_layout_;
  GLFWwindow *window_;
  std::unique_ptr<AbstractStream> startup_stream_;  // opened on the first frame
  StreamLoader startup_loader_;  // run on a worker after the first frame
  DummyStream dummy_;
  std::unique_ptr<ChartsWidget> charts_widget_;
  StreamSelector stream_selector_;
  SettingsDialog settings_dialog_;
  HelpOverlay help_overlay_;
  std::unordered_map<std::string, std::string> fingerprint_to_dbc_;
  std::vector<std::string> opendbc_names_;
  enum { MAX_RECENT_FILES = 15 };
  bool charts_visible_ = true;
  bool playback_visible_ = true;
  bool reset_layout_ = false;
  bool full_screen_ = false;
#ifndef __APPLE__
  int windowed_rect_[4] = {0, 0, 1600, 900};
#endif
  bool closing_ = false;
  bool exited_ = false;
  bool window_modified_ = false;
  struct StatusBar {
    std::string message;
    double message_until = 0;
    bool progress_visible = false;
    float progress_value = 0;
    std::string progress_text;
  } status_bar_;
  // "Loading segment data..." dialog
  struct WaitDialog {
    bool open = false;
    double show_at = 0;
    std::string text;
    int value = 0;
    Connection connection;
  } wait_dlg_;
  std::vector<std::function<void()>> next_frame_;
  Connections connections_;
};
