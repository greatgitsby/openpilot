#include "tools/cabana/ui/widgets/seriesbrowser.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/icons.h"

void SeriesBrowser::draw(cabana::AnalysisSession &session, const std::function<void(const std::string &, bool)> &plot) {
  if (checkBox("Show deprecated fields", &show_deprecated_)) revision_ = 0;
  if (revision_ != session.revision()) {
    auto sources = session.sources();
    if (!show_deprecated_) sources.erase(std::remove_if(sources.begin(), sources.end(), [](const auto &path) { return path.find("DEPRECATED") != std::string::npos; }), sources.end());
    sources_ = std::move(sources);
    tree_.rebuild(sources_);
    for (auto &node : tree_.nodes) if (node.path.rfind("equation/", 0) == 0) node.name = session.displayName(node.path);
    tree_.filter(filter_);
    revision_ = session.revision();
  }
  if (clearableInput("##series_filter", &filter_, "Search fields and functions...")) tree_.filter(filter_);
  ImGui::TextDisabled("Double-click to plot. Drag onto a chart to overlay.");
  if (beginControlChild("series_tree", ImVec2(0, 0))) {
    auto expanded = expanded_;
    if (!filter_.empty()) for (const auto &node : tree_.nodes) if (node.matches) expanded.insert(node.key);
    auto rows = tree_.visible(expanded);
    ImGuiListClipper clipper;
    clipper.Begin(rows.size());
    while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const auto &node = tree_.nodes[rows[row]];
      ImGui::PushID(node.key.c_str());
      ImGui::Indent(node.depth * ImGui::GetStyle().IndentSpacing);
      const bool open = expanded.count(node.key);
      std::string label = (node.children.empty() ? "" : open ? "- " : "+ ") + node.name;
      if (selectable(label.c_str(), false) && !node.children.empty()) {
        if (open) expanded_.erase(node.key); else expanded_.insert(node.key);
      }
      if (!node.path.empty()) {
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) plot(node.path, ImGui::GetIO().KeyShift);
        if (ImGui::BeginDragDropSource()) {
          ImGui::SetDragDropPayload("CABANA_SERIES", node.path.c_str(), node.path.size() + 1);
          ImGui::TextUnformatted(node.path.c_str());
          ImGui::EndDragDropSource();
        }
        if (ImGui::IsItemHovered()) {
          const auto metadata = cabana::describeField(node.path);
          std::string text = node.path;
          for (const auto &[value, name] : metadata.enumerants) text += "\n" + std::to_string(value) + ": " + name;
          ImGui::SetItemTooltip("%s", text.c_str());
        }
      }
      ImGui::Unindent(node.depth * ImGui::GetStyle().IndentSpacing);
      ImGui::PopID();
    }
  }
  ImGui::EndChild();
}

std::string droppedSeries(const ImRect &area) {
  std::string source;
  if (ImGui::BeginDragDropTargetCustom(area, ImGui::GetID("series_drop"))) {
    if (auto *payload = ImGui::AcceptDragDropPayload("CABANA_SERIES")) source = static_cast<const char *>(payload->Data);
    ImGui::EndDragDropTarget();
  }
  return source;
}
