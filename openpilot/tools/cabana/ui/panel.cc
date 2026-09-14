#include "tools/cabana/ui/panel.h"
#include "tools/cabana/ui/util.h"

#include <algorithm>
#include <set>
#include <map>

namespace { std::map<ImGuiID, int> pending_tab_focus; }

// closing a panel that floated out into its own os window brings it back into the default layout, only
// the close button of a docked panel hides it
bool floatingOut() { return ImGui::GetWindowViewport() != ImGui::GetMainViewport(); }

// the side panels float out like the dialogs, and their dock nodes have no window menu button: its
// only entry hides the tab bar, and with it the title and the close button
void setNextPanelClass() {
  ImGuiWindowClass window_class;
  window_class.ViewportFlagsOverrideSet = ImGuiViewportFlags_NoAutoMerge;
  window_class.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoWindowMenuButton;
  ImGui::SetNextWindowClass(&window_class);
}

bool beginPanel(const char *name, bool *open, ImGuiWindowFlags flags, bool pad_content) {
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, pad_content ? contentPadding(ContentPadding::Panel) : ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  const bool visible = ImGui::Begin(name, open, flags | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoFocusOnAppearing);
  if (auto it = pending_tab_focus.find(ImHashStr(name)); it != pending_tab_focus.end()) {
    auto *window = ImGui::GetCurrentWindow();
    if (window->DockNode && window->DockNode->TabBar) {
      window->DockNode->SelectedTabId = window->TabId;
      window->DockNode->TabBar->SelectedTabId = window->TabId;
      window->DockNode->TabBar->NextSelectedTabId = window->TabId;
      if (!ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) ImGui::FocusWindow(window);
      if (--it->second <= 0) pending_tab_focus.erase(it);
    }
  }
  ImGui::PopStyleVar(2);
  return visible;
}

namespace docking {
namespace {
std::string identity(const char *name) {
  std::string result(name);
  auto pos = result.find("###");
  return pos == std::string::npos ? result : result.substr(pos);
}
json11::Json captureNode(ImGuiDockNode *node) {
  using J = json11::Json;
  if (!node) return J::object{};
  if (node->IsSplitNode()) {
    const bool horizontal = node->SplitAxis == ImGuiAxis_X;
    const float first = horizontal ? node->ChildNodes[0]->SizeRef.x : node->ChildNodes[0]->SizeRef.y;
    const float second = horizontal ? node->ChildNodes[1]->SizeRef.x : node->ChildNodes[1]->SizeRef.y;
    return J::object{{"axis", horizontal ? "x" : "y"}, {"ratio", first / std::max(first + second, 1.0f)},
                     {"children", J::array{captureNode(node->ChildNodes[0]), captureNode(node->ChildNodes[1])}}};
  }
  J::array panes;
  std::string selected;
  for (const auto *window : node->Windows) {
    panes.push_back(identity(window->Name));
    if (window->TabId == node->SelectedTabId) selected = identity(window->Name);
  }
  return J::object{{"panes", panes}, {"selected", selected}};
}
void restoreNode(ImGuiID id, const json11::Json &tree) {
  const auto &children = tree["children"].array_items();
  if (children.size() == 2) {
    ImGuiID first, second;
    ImGui::DockBuilderSplitNode(id, tree["axis"].string_value() == "x" ? ImGuiDir_Left : ImGuiDir_Up,
                               std::clamp((float)tree["ratio"].number_value(), 0.01f, 0.99f), &first, &second);
    restoreNode(first, children[0]);
    restoreNode(second, children[1]);
  } else {
    for (const auto &pane : tree["panes"].array_items()) ImGui::DockBuilderDockWindow(pane.string_value().c_str(), id);
    if (!tree["selected"].string_value().empty()) {
      if (auto *node = ImGui::DockBuilderGetNode(id)) node->SelectedTabId = ImHashStr("#TAB", 0, ImHashStr(tree["selected"].string_value().c_str()));
      pending_tab_focus[ImHashStr(tree["selected"].string_value().c_str())] = 3;
    }
  }
}
}
json11::Json capture(ImGuiID root) { return captureNode(ImGui::DockBuilderGetNode(root)); }
void restore(ImGuiID root, const json11::Json &tree, const ImVec2 &position, const ImVec2 &size) {
  ImGui::DockBuilderRemoveNode(root);
  ImGui::DockBuilderAddNode(root, ImGuiDockNodeFlags_DockSpace);
  ImGui::DockBuilderSetNodePos(root, position);
  ImGui::DockBuilderSetNodeSize(root, size);
  restoreNode(root, tree);
  ImGui::DockBuilderFinish(root);
  const auto *viewport = ImGui::GetMainViewport();
  for (const auto &floating : tree["floating"].array_items()) {
    ImGuiID id = ImGui::DockBuilderAddNode(0, ImGuiDockNodeFlags_None);
    ImGui::DockBuilderSetNodePos(id, ImVec2(viewport->Pos.x + floating["x"].number_value() * viewport->Size.x,
                                          viewport->Pos.y + floating["y"].number_value() * viewport->Size.y));
    ImGui::DockBuilderSetNodeSize(id, ImVec2(std::max(100.0, floating["width"].number_value() * viewport->Size.x),
                                           std::max(100.0, floating["height"].number_value() * viewport->Size.y)));
    std::function<void(const json11::Json &)> position_windows = [&](const json11::Json &subtree) {
      for (const auto &pane : subtree["panes"].array_items()) {
        if (ImGui::FindWindowByName(pane.string_value().c_str())) {
          ImGui::SetWindowPos(pane.string_value().c_str(), ImGui::DockBuilderGetNode(id)->Pos);
          ImGui::SetWindowSize(pane.string_value().c_str(), ImGui::DockBuilderGetNode(id)->Size);
        }
      }
      for (const auto &child : subtree["children"].array_items()) position_windows(child);
    };
    position_windows(floating["tree"]);
    restoreNode(id, floating["tree"]);
    ImGui::DockBuilderFinish(id);
    if (auto *node = ImGui::DockBuilderGetNode(id)) {
      node->AuthorityForPos = ImGuiDataAuthority_DockNode;
      node->AuthorityForSize = ImGuiDataAuthority_DockNode;
    }
  }
}
void keepAlive(ImGuiID root) { ImGui::DockSpace(root, ImVec2(0, 0), ImGuiDockNodeFlags_KeepAliveOnly); }
}

namespace docking {
void Workspace::draw(const std::string &page, const std::vector<std::string> &pages, const json11::Json &default_layout,
                     const std::function<json11::Json(const std::string &)> &read,
                     const std::function<void(const std::string &, const json11::Json &)> &write,
                     const ImVec2 &size, bool reset, uint64_t revision) {
  auto dockId = [](const std::string &id) { return ImHashStr(("CabanaWorkspace/" + id).c_str()); };
  const ImGuiID root = dockId(page);
  const bool replaced = revision_ != revision;
  if (!replaced && !active_page_.empty() && active_page_ != "loading" && ImGui::DockBuilderGetNode(dockId(active_page_))) {
    auto layout = capture(dockId(active_page_)).object_items();
    json11::Json::array floating;
    std::set<ImGuiID> captured;
    const auto *viewport = ImGui::GetMainViewport();
    for (const auto &name : active_windows_) {
      const auto *window = ImGui::FindWindowByName(name.c_str());
      if (!window || !window->WasActive) continue;
      auto *node = window->DockNode;
      while (node && node->ParentNode) node = node->ParentNode;
      if (node && node->ID == dockId(active_page_)) continue;
      if (!captured.insert(node ? node->ID : window->ID).second) continue;
      const auto position = node ? node->Pos : window->Pos;
      const auto floating_size = node ? node->Size : window->Size;
      const auto tree = node ? captureNode(node) : json11::Json(json11::Json::object{{"panes", json11::Json::array{identity(name.c_str())}}});
      floating.push_back(json11::Json::object{{"tree", tree}, {"x", (position.x - viewport->Pos.x) / viewport->Size.x},
        {"y", (position.y - viewport->Pos.y) / viewport->Size.y}, {"width", floating_size.x / viewport->Size.x}, {"height", floating_size.y / viewport->Size.y}});
    }
    layout["floating"] = floating;
    write(active_page_, layout);
  }
  // Only additions to the current document are automatic. Restored floating panes stay floating.
  if (!replaced && active_page_ == page) {
    std::function<void(const json11::Json &)> discover = [&](const json11::Json &tree) {
      for (const auto &pane : tree["panes"].array_items()) {
        const auto name = identity(pane.string_value().c_str());
        if (name.rfind("###Chart/", 0) == 0 && std::find(active_windows_.begin(), active_windows_.end(), name) == active_windows_.end() &&
            std::none_of(pending_windows_.begin(), pending_windows_.end(), [&](const auto &pending) { return identity(pending.c_str()) == name; })) pending_windows_.push_back(name);
      }
      for (const auto &child : tree["children"].array_items()) discover(child);
    };
    discover(default_layout);
  }
  if (reset || replaced || active_page_ != page || !ImGui::DockBuilderGetNode(root)) {
    auto layout = reset ? json11::Json() : read(page);
    restore(root, layout.is_null() ? default_layout : layout, ImGui::GetCursorScreenPos(), size);
    active_page_ = page;
    revision_ = revision;
  }
  if (!pending_windows_.empty()) {
    for (const auto &name : pending_windows_) {
      auto *target = ImGui::DockBuilderGetNode(root);
      const bool chart = identity(name.c_str()).rfind("###Chart/", 0) == 0;
      ImGuiDockNode *plot_node = nullptr;
      ImGuiDockNode *largest_leaf = nullptr;
      std::function<void(ImGuiDockNode *)> find_plot = [&](ImGuiDockNode *node) {
        if (!node) return;
        if (!node->IsSplitNode() && (!largest_leaf || node->Size.x * node->Size.y > largest_leaf->Size.x * largest_leaf->Size.y)) largest_leaf = node;
        for (const auto *window : node->Windows) {
          if (identity(window->Name).rfind("###Chart/", 0) == 0 && (!plot_node || node->Size.y > plot_node->Size.y)) plot_node = node;
        }
        for (auto *child : node->ChildNodes) find_plot(child);
      };
      find_plot(target);
      ImGuiID destination = root;
      if (chart && plot_node) {
        // Stack plots while there is useful room; use tabs rather than creating tiny slivers.
        destination = plot_node->ID;
        if (plot_node->Size.y >= ImGui::GetFontSize() * 18)
          destination = ImGui::DockBuilderSplitNode(destination, ImGuiDir_Down, .5f, nullptr, nullptr);
      } else if (target && (target->IsSplitNode() || !target->Windows.empty())) {
        const auto id = identity(name.c_str());
        const bool browser = id == "###ChartsWindow" || id == "###MessagesPanel";
        // Add beside the largest pane rather than repeatedly squeezing the whole page.
        auto *leaf = largest_leaf ? largest_leaf : target;
        destination = leaf->ID;
        if (leaf->Size.x >= ImGui::GetFontSize() * 40) {
          const float ratio = browser && leaf == target ? .25f : .5f;
          destination = ImGui::DockBuilderSplitNode(leaf->ID, browser ? ImGuiDir_Left : ImGuiDir_Right,
                                                    ratio, nullptr, nullptr);
        }
      }
      ImGui::DockBuilderDockWindow(name.c_str(), destination);
      pending_tab_focus[ImHashStr(name.c_str())] = 3;
    }
    ImGui::DockBuilderFinish(root);
    pending_windows_.clear();
  }
  active_windows_.clear();
  std::function<void(const json11::Json &)> collect = [&](const json11::Json &tree) {
    for (const auto &name : tree["panes"].array_items()) active_windows_.push_back(identity(name.string_value().c_str()));
    for (const auto &child : tree["children"].array_items()) collect(child);
  };
  collect(default_layout);
  for (const auto &id : pages) if (id != page) keepAlive(dockId(id));
  ImGui::DockSpace(root, size);
}
}
