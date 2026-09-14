#pragma once
#include <cstdint>

#include "imgui.h"
#include "imgui_internal.h"

// Shared presentation for dockable Cabana panels. Always pair beginPanel with End.
bool floatingOut();
void setNextPanelClass();
bool beginPanel(const char *name, bool *open, ImGuiWindowFlags flags = 0, bool pad_content = true);

#include <string>
#include <vector>
#include "json11/json11.hpp"

// Semantic dock trees use proportional splits and stable window identities.
namespace docking {
json11::Json capture(ImGuiID root);
void restore(ImGuiID root, const json11::Json &tree, const ImVec2 &position, const ImVec2 &size);
void keepAlive(ImGuiID root);
}

#include <functional>
namespace docking {
class Workspace {
public:
  void addWindow(const std::string &name) { pending_windows_.push_back(name); }
  void draw(const std::string &page, const std::vector<std::string> &pages, const json11::Json &default_layout,
            const std::function<json11::Json(const std::string &)> &read,
            const std::function<void(const std::string &, const json11::Json &)> &write,
            const ImVec2 &size, bool reset, uint64_t revision);
private:
  std::string active_page_;
  uint64_t revision_ = 0;
  std::vector<std::string> active_windows_;
  std::vector<std::string> pending_windows_;
};
}
