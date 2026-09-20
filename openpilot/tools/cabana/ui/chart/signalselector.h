#pragma once

#include <string>
#include <vector>

#include "imgui.h"
#include "tools/cabana/dbc/dbcmanager.h"

// non-blocking: open(), draw() every frame until it returns false, then check accepted()
class SignalSelector {
public:
  struct ListItem {
    ListItem(const MessageId &msg_id, const cabana::Signal *sig, std::string source_id = {}) : source_id(std::move(source_id)), msg_id(msg_id), sig(sig) {}
    ListItem(std::string path, std::string source_id = {}) : source_id(std::move(source_id)), path(std::move(path)), sig(nullptr) {}
    std::string source_id;
    std::string path;
    std::string name() const { return path.empty() ? sig->name : path; }
    MessageId msg_id;
    const cabana::Signal *sig;
  };

  SignalSelector(std::string title);
  const std::vector<ListItem> &selectedItems() const { return selected_list_; }
  inline void addSelected(const MessageId &id, const cabana::Signal *sig, const std::string &source_id = {}) { selected_list_.emplace_back(id, sig, source_id); }
  void addFields(const std::string &path, const std::string &source_id = {}) { selected_list_.emplace_back(path, source_id); }
  void open() { open_ = true; show_ = false; accepted_ = false; }
  bool draw();  // false once the dialog is closed
  bool accepted() const { return accepted_; }

private:
  void updateAvailableList();
  void add(int row);
  void remove(int row);
  void drawList(const char *id, std::vector<ListItem> &list, int *current_row, bool show_msg_name, bool *double_clicked, const ImVec2 &size);

  struct ComboItem {
    std::string text;
    MessageId id;
  };
  std::string source_id_;
  std::string title_;
  std::vector<ComboItem> msgs_combo_;
  std::string msgs_combo_filter_;
  std::vector<ListItem> available_list_;
  std::vector<ListItem> selected_list_;
  int available_row_ = -1;
  int selected_row_ = -1;
  bool available_dirty_ = true;
  bool accepted_ = false;
  bool open_ = false;
  bool show_ = false;
};
