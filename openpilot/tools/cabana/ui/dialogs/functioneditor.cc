#include "tools/cabana/ui/dialogs/functioneditor.h"
#include "tools/cabana/ui/icons.h"

void FunctionEditor::draw() {
  if (!open_ || !beginDialog("Python Function", &popup_, ImVec2(680, 620), 0)) return;
  ImGui::TextUnformatted("Name");
  ImGui::SetNextItemWidth(-1);
  inputText("##name", &draft_.name);
  ImGui::TextUnformatted("Primary source (value)");
  ImGui::SetNextItemWidth(-1);
  inputText("##source", &draft_.source, "/carState/vEgo or can/0:123|SPEED");
  ImGui::TextDisabled("time is the boot timestamp in seconds. Additional inputs use the nearest sample.");
  if (iconButton("add_input", icon::PLUS_LG, "Add input") && draft_.additional.size() < 32) draft_.additional.emplace_back();
  int remove = -1;
  for (int i = 0; i < draft_.additional.size(); ++i) {
    ImGui::PushID(i);
    ImGui::SetNextItemWidth(-80);
    inputText(("v" + std::to_string(i + 1)).c_str(), &draft_.additional[i]);
    ImGui::SameLine();
    if (iconButton("remove", icon::X_LG, "Remove input")) remove = i;
    ImGui::PopID();
  }
  if (remove >= 0) draft_.additional.erase(draft_.additional.begin() + remove);
  ImGui::TextUnformatted("Initialization (runs once per recomputation)");
  inputTextMultiline("##globals", &draft_.globals, ImVec2(-1, 90), ImGuiInputTextFlags_AllowTabInput);
  ImGui::TextUnformatted("Python function body");
  inputTextMultiline("##function", &draft_.function, ImVec2(-1, 180), ImGuiInputTextFlags_AllowTabInput);
  ImGui::TextDisabled("Return a number or (time, value). Numeric math and initialized global state are supported.");
  bool save = false, cancel = false;
  dialogButtons("Save", &save, &cancel, !draft_.name.empty() && !draft_.source.empty() && !draft_.function.empty());
  if (save || cancel) {
    open_ = false;
    ImGui::CloseCurrentPopup();
    if (save) save_(draft_);
  }
  ImGui::EndPopup();
}
