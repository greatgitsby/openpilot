#pragma once

#include <string>
#include <vector>

#include "imgui.h"
#include "tools/cabana/dbc/dbcmanager.h"

// chart signals and selector items are a CAN signal (msg_id + signal_name) or a log field or function (path) of one source
template <typename A, typename B>
bool sameSignal(const A &a, const B &b) {
  return a.source_id == b.source_id && a.path == b.path && a.msg_id == b.msg_id && a.signal_name == b.signal_name;
}

// non-blocking: open(), draw() every frame until it returns false, then check accepted()
class SignalSelector {
public:
  struct ListItem {
    std::string source_id, path;
    MessageId msg_id;
    std::string signal_name;
    CabanaColor color{0, 114, 178};
  };

  SignalSelector(std::string title);
  const std::vector<ListItem> &selectedItems() const { return selected_list_; }
  void addSelected(const ListItem &item) { selected_list_.push_back(item); }
  void open() { open_ = true; show_ = false; accepted_ = false; }
  bool draw();  // false once the dialog is closed
  bool accepted() const { return accepted_; }

private:
  void updateAvailableList();
  void drawList(const char *id, std::vector<ListItem> &list, int *current_row, bool show_msg_name, bool *double_clicked, const ImVec2 &size);

  std::string source_id_;
  std::string title_;
  std::string filter_;
  std::vector<ListItem> available_list_;
  std::vector<ListItem> selected_list_;
  int available_row_ = -1;
  int selected_row_ = -1;
  bool available_dirty_ = true;
  bool accepted_ = false;
  bool open_ = false;
  bool show_ = false;
};
