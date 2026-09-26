#include "tools/cabana/ui/chart/signalselector.h"

#include <algorithm>
#include <cfloat>
#include <map>

#include "imgui.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"

SignalSelector::SignalSelector(std::string title) : source_id_(can->source_id), title_(std::move(title)) {}

bool SignalSelector::draw() {
  if (!open_) return false;
  const std::string popup_id = title_ + "###SignalSelector";
  if (!show_) {
    ImGui::OpenPopup(popup_id.c_str());
    show_ = true;
  }
  setNextDialogWindow(ImVec2(700.0f, 450.0f));
  if (!ImGui::BeginPopupModal(popup_id.c_str(), nullptr, ImGuiWindowFlags_NoSavedSettings)) {
    open_ = false;
    return false;
  }

  auto *source = sourceById(source_id_);
  if (!source && !sources().empty()) { source = sources().front(); source_id_ = source->source_id; available_dirty_ = true; }
  menuButton("signal_source", "Source: " + (source ? source->source_label : std::string("No sources")), "signal_sources", false, -1);
  if (dropdown::BeginPopup("signal_sources")) {
    for (auto *candidate : sources()) {
      ImGui::PushID(candidate->source_id.c_str());
      if (dropdown::Item(candidate->source_label.c_str(), nullptr, candidate == source)) {
        source_id_ = candidate->source_id;
        available_dirty_ = true;
      }
      ImGui::PopID();
    }
    dropdown::EndPopup();
  }
  const float btn_w = iconButtonWidth();
  const float column_w = (ImGui::GetContentRegionAvail().x - btn_w - ImGui::GetStyle().ItemSpacing.x * 2) / 2;
  // the selected list spans the search row too; both lists end above the Ok/Cancel row
  const float lists_h = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 3;

  ImGui::BeginGroup();
  ImGui::AlignTextToFramePadding();
  ImGui::TextUnformatted("Available Signals");
  ImGui::SetNextItemWidth(column_w);
  if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
  available_dirty_ |= inputText("##signal_search", &filter_, "Search signals, messages, or IDs...");
  if (std::exchange(available_dirty_, false)) updateAvailableList();
  bool add_dbl = false;
  drawList("##available_list", available_list_, &available_row_, true, &add_dbl, ImVec2(column_w, lists_h));
  ImGui::EndGroup();

  ImGui::SameLine();
  ImGui::BeginGroup();
  ImGui::Dummy(ImVec2(btn_w, (lists_h + ImGui::GetFrameHeightWithSpacing() * 2) / 2 - ImGui::GetFrameHeight()));
  ImGui::BeginDisabled(available_row_ == -1);
  bool add_clicked = iconButton("add", icon::CHEVRON_RIGHT, "Add");
  ImGui::EndDisabled();
  ImGui::BeginDisabled(selected_row_ == -1);
  bool remove_clicked = iconButton("remove", icon::CHEVRON_LEFT, "Remove");
  ImGui::EndDisabled();
  ImGui::EndGroup();

  ImGui::SameLine();
  ImGui::BeginGroup();
  ImGui::AlignTextToFramePadding();
  ImGui::TextUnformatted("Selected Signals");
  bool remove_dbl = false;
  drawList("##selected_list", selected_list_, &selected_row_, true, &remove_dbl, ImVec2(column_w, lists_h + ImGui::GetFrameHeightWithSpacing()));
  bool rejected = false;
  dialogButtons("OK", &accepted_, &rejected);
  const bool done = accepted_ || rejected;
  ImGui::EndGroup();

  if ((add_dbl || add_clicked) && available_row_ >= 0 && available_row_ < (int)available_list_.size()) {
    selected_list_.push_back(available_list_[available_row_]);
    available_dirty_ = true;
  } else if ((remove_dbl || remove_clicked) && selected_row_ >= 0 && selected_row_ < (int)selected_list_.size()) {
    selected_list_.erase(selected_list_.begin() + selected_row_);
    selected_row_ = -1;
    available_dirty_ = true;
  }

  if (done) {
    open_ = false;
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndPopup();
  return open_;
}

void SignalSelector::drawList(const char *id, std::vector<ListItem> &list, int *current_row, bool show_msg_name, bool *double_clicked, const ImVec2 &size) {
  if (!ImGui::BeginListBox(id, size)) return;
  ImGuiListClipper clipper;
  clipper.Begin(list.size());
  while (clipper.Step()) for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
    const auto &item = list[i];
    auto *source = sourceById(item.source_id);
    SourceScope source_scope(source);  // msgLabel() names the message from the item's DBC
    ImGui::PushID(i);
    const ImVec2 pos = ImGui::GetCursorScreenPos();
    if (selectable("##item", i == *current_row)) *current_row = i;
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
      *current_row = i;
      *double_clicked = true;
    }
    // label: colored square, signal name, then the message name/id and the source in gray
    ImDrawList *dl = ImGui::GetWindowDrawList();
    float x = pos.x + 5;
    drawColorMarker(dl, ImVec2(x, pos.y), toImU32(item.color));
    x += markerSize() + 4;
    const std::string &name = item.path.empty() ? item.signal_name : item.path;
    dl->AddText(ImVec2(x, pos.y), ImGui::GetColorU32(i == *current_row ? palette().text_selected : palette().text), name.c_str());
    if (show_msg_name) {
      x += ImGui::CalcTextSize(name.c_str()).x;
      const std::string detail = (item.path.empty() ? msgLabel(item.msg_id) : "") + " · " + (source ? source->source_label : item.source_id);
      dl->AddText(ImVec2(x, pos.y), ImGui::GetColorU32(i == *current_row ? palette().text_selected : palette().text_disabled), detail.c_str());
    }
    ImGui::PopID();
  }
  ImGui::EndListBox();
}

void SignalSelector::updateAvailableList() {
  available_list_.clear();
  available_row_ = -1;
  auto *source = sourceById(source_id_);
  if (!source) return;
  auto add = [&](const ListItem &item, const std::string &text) {
    if (utils::containsCI(text, filter_) &&
        std::none_of(selected_list_.begin(), selected_list_.end(), [&](const auto &s) { return sameSignal(s, item); })) available_list_.push_back(item);
  };
  std::map<std::string, MessageId> messages;  // sorted by name
  auto addMessage = [&](const MessageId &id) {
    if (auto *m = source->database()->msg(id)) messages.emplace(m->name + " (" + id.toString() + ")", id);
  };
  for (const auto &[id, _] : source->eventsMap()) addMessage(id);
  for (const auto &[id, _] : source->lastMessages()) addMessage(id);
  for (const auto &[text, id] : messages) {
    for (auto *sig : source->database()->msg(id)->getSignals()) add({source_id_, "", id, sig->name, sig->color}, sig->name + " " + text);
  }
  for (const auto &[path, _] : source->fields) add({source_id_, path}, path);
}
