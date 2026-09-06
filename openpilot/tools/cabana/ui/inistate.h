#pragma once
#include <string>

struct GLFWwindow;

// The imgui frontend's persisted state: the imgui ini text (windows, dock layout, table
// state) plus a custom [Cabana][MainWindow] section, stored as one string in Settings.
namespace inistate {

// the dock panes of the main window, in the order of the View menu
enum Pane { PaneMessages = 0, PaneMessage, PaneVideo, PaneCharts, kPaneCount };
inline constexpr const char *kPaneIniKeys[kPaneCount] = {"MessagesVisible", "MessageVisible", "VideoVisible", "ChartsVisible"};

struct MainWindowState {
  int pos[2] = {0, 0};
  int size[2] = {0, 0};
  bool maximized = false;
  bool has_geometry = false;
  bool pane_visible[kPaneCount] = {true, true, true, true};
};

extern MainWindowState main_window;

void addSettingsHandler();                    // register the [Cabana] ini section
void load();                                  // migrate Qt state if needed, then LoadIniSettingsFromMemory
void applyWindowGeometry(GLFWwindow *window); // glfw pos/size/maximize from main_window
std::string save();                           // SaveIniSettingsToMemory (caller fills main_window first)

}  // namespace inistate
