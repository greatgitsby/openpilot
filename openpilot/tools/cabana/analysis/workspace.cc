#include "tools/cabana/analysis/workspace.h"
#include <set>
#include <cmath>
#include <functional>
#include <cstdio>
#include <map>
#include <algorithm>
#include "tools/cabana/core/message_id.h"

namespace cabana {
std::string validateWorkspace(const json11::Json &doc) {
  if (doc["cabana_workspace"].int_value() != 1) return "Unsupported workspace version";
  if (doc["pages"].array_items().empty()) return "Workspace requires at least one page";
  std::set<std::string> pages, panes, equations;
  for (const auto &e : doc["equations"].array_items()) {
    if (e["language"].string_value() != "python") return "Unsupported equation language: only Python is supported";
    if (e["id"].string_value().empty() || !equations.insert(e["id"].string_value()).second) return "Missing or duplicate equation ID";
  }
  for (const auto &page : doc["pages"].array_items()) {
    std::set<std::string> allowed{"###MessagesPanel", "###CenterWidget", "###VideoPanel", "###ChartsWindow", "###WideCameraPanel", "###CabinCameraPanel"};
    if (!page["widgets"].is_null()) {
      if (!page["widgets"].is_array()) return "Invalid widget list";
      std::set<std::string> widgets;
      for (const auto &id : page["widgets"].array_items())
        if (!allowed.count(id.string_value()) || !widgets.insert(id.string_value()).second) return "Unknown or duplicate widget";
    }
    for (const auto &pane : page["panes"].array_items()) allowed.insert("###Chart/" + pane["id"].string_value());
    std::set<std::string> placed;
    std::function<bool(const json11::Json &, int)> validTree = [&](const json11::Json &tree, int depth) {
      if (!tree.is_object() || depth > 64) return false;
      if (!tree["children"].is_null()) {
        const auto axis = tree["axis"].string_value();
        const double ratio = tree["ratio"].number_value();
        if ((axis != "x" && axis != "y") || !(ratio > 0 && ratio < 1) || tree["children"].array_items().size() != 2) return false;
        for (const auto &child : tree["children"].array_items()) if (!validTree(child, depth + 1)) return false;
      } else {
        if (!tree["panes"].is_array()) return false;
        std::set<std::string> leaf;
        for (const auto &pane : tree["panes"].array_items()) {
          const auto &id = pane.string_value();
          if (!allowed.count(id) || !placed.insert(id).second) return false;
          leaf.insert(id);
        }
        if (!tree["selected"].string_value().empty() && !leaf.count(tree["selected"].string_value())) return false;
      }
      return true;
    };
    const auto &dock = page["dock"];
    if (!dock.is_null()) {
      if (!validTree(dock, 0)) return "Invalid dock arrangement";
      for (const auto &floating : dock["floating"].array_items()) {
        for (const auto *key : {"x", "y", "width", "height"}) if (!floating[key].is_number() || !std::isfinite(floating[key].number_value())) return "Invalid floating geometry";
        if (floating["width"].number_value() <= 0 || floating["height"].number_value() <= 0 || !validTree(floating["tree"], 0)) return "Invalid floating arrangement";
      }
    }
    if (page["id"].string_value().empty() || !pages.insert(page["id"].string_value()).second) return "Missing or duplicate page ID";
    for (const auto &pane : page["panes"].array_items()) {
      if (pane["id"].string_value().empty() || !panes.insert(pane["id"].string_value()).second) return "Missing or duplicate pane ID";
      if (pane["y_lower"].is_number() && pane["y_upper"].is_number() && pane["y_lower"].number_value() >= pane["y_upper"].number_value()) return "Invalid vertical bounds";
      if (pane["style"].int_value() < 0 || pane["style"].int_value() > 2) return "Unsupported plot style";
      for (const auto &curve : pane["curves"].array_items()) {
        const auto &transform = curve["transform"];
        if (transform["type"].int_value() < 0 || transform["type"].int_value() > 3) return "Unsupported transform";
        for (const auto *key : {"scale", "offset", "time_offset", "divisor"}) {
          if (!transform[key].is_null() && (!transform[key].is_number() || !std::isfinite(transform[key].number_value()))) return "Invalid transform parameter";
        }
        const auto &source = curve["source"];
        const auto &kind = source["kind"].string_value();
        if (kind != "can" && kind != "series") return "Unsupported series kind";
        if (source["path"].string_value().empty()) return "Missing series path";
        if (kind == "can" && !MessageId::parse(source["message"].string_value())) return "Invalid CAN message ID";
      }
    }
  }
  return {};
}
}

namespace cabana {
json11::Json migrateWorkspace(const json11::Json &doc) {
  using J = json11::Json;
  if (!doc["cabana_workspace"].is_null() || !doc["tabs"].is_array()) return doc;
  J::array equations, pages;
  std::map<std::string, std::string> refs;
  for (const auto &item : doc["equations"].array_items()) refs[item["name"].string_value()] = "equation/legacy-" + item["name"].string_value();
  auto reference = [&](const std::string &path) { return refs.count(path) ? refs.at(path) : path; };
  for (const auto &item : doc["equations"].array_items()) {
    auto equation = item.object_items();
    equation["id"] = "legacy-" + item["name"].string_value();
    equation["source"] = reference(item["source"].string_value());
    J::array additional;
    for (const auto &input : item["additional"].array_items()) additional.push_back(reference(input.string_value()));
    equation["additional"] = additional;
    equations.push_back(equation);
  }
  int page_index = 0;
  for (const auto &tab : doc["tabs"].array_items()) {
    J::array panes;
    std::vector<J> leaves;
    for (const auto &chart : tab.array_items()) {
      J::array curves;
      for (const auto &signal : chart["signals"].array_items()) {
        const auto path = signal["path"].string_value();
        const J source = path.empty() ? J(J::object{{"kind", "can"}, {"message", signal["message"]}, {"path", signal["signal"]}})
                                      : J(J::object{{"kind", "series"}, {"path", reference(path)}});
        unsigned color = 0x0072b2;
        if (signal["color"].is_string()) sscanf(signal["color"].string_value().c_str(), "#%x", &color);
        curves.push_back(J::object{{"source", source},
          {"visible", signal["visible"].is_bool() ? signal["visible"] : J(true)}, {"color", J::array{(int)(color >> 16 & 255), (int)(color >> 8 & 255), (int)(color & 255), 255}},
          {"transform", J::object{{"type", signal["transform"].int_value()},
            {"scale", signal["scale"].is_number() ? signal["scale"] : J(1)}, {"offset", signal["offset"].number_value()},
            {"divisor", 0}, {"window", signal["window"].is_number() ? signal["window"] : J(10)}}}});
      }
      const auto id = "legacy-pane-" + std::to_string(page_index) + "-" + std::to_string(panes.size());
      panes.push_back(J::object{{"id", id}, {"title", chart["title"]}, {"style", chart["type"]}, {"curves", curves},
                                {"y_lower", chart["y_min"]}, {"y_upper", chart["y_max"]}});
      leaves.push_back(J::object{{"panes", J::array{"###Chart/" + id}}});
    }
    auto combine = [](const std::vector<J> &nodes, const char *axis) -> J {
      if (nodes.empty()) return J::object{{"panes", J::array{}}};
      J tree = nodes.back();
      for (int i = (int)nodes.size() - 2; i >= 0; --i) tree = J::object{{"axis", axis}, {"ratio", 1.0 / (nodes.size() - i)}, {"children", J::array{nodes[i], tree}}};
      return tree;
    };
    const int columns = std::clamp(doc["columns"].int_value(), 1, 4);
    std::vector<J> rows;
    for (size_t i = 0; i < leaves.size(); i += columns) {
      rows.push_back(combine(std::vector<J>(leaves.begin() + i, leaves.begin() + std::min(i + columns, leaves.size())), "x"));
    }
    auto name = doc["tab_names"][page_index].string_value();
    if (name.empty()) name = "Page " + std::to_string(page_index + 1);
    pages.push_back(J::object{{"id", "legacy-page-" + std::to_string(page_index++)}, {"name", name}, {"panes", panes},
      {"dock", J::object{{"axis", "x"}, {"ratio", 0.22}, {"children", J::array{
        J::object{{"panes", J::array{"###MessagesPanel", "###CenterWidget", "###VideoPanel", "###ChartsWindow"}}}, combine(rows, "y")}}}}});
  }
  return J::object{{"cabana_workspace", 1}, {"pages", pages}, {"equations", equations}, {"active_page", 0}, {"relative_time", true}};
}
}

json11::Json cabana::browserPageLayout() {
  using J = json11::Json;
  return J::object{{"axis", "x"}, {"ratio", .18}, {"children", J::array{
    J::object{{"panes", J::array{"###ChartsWindow"}}}, J::object{{"panes", J::array{}}}}}};
}

json11::Json cabana::blankWorkspace() {
  using J = json11::Json;
  return J::object{{"cabana_workspace", 1}, {"active_page", 0}, {"equations", J::array{}},
    {"pages", J::array{J::object{{"id", "page-1"}, {"name", "Page 1"}, {"panes", J::array{}},
                               {"widgets", J::array{"###ChartsWindow"}}, {"dock", browserPageLayout()}}}}};
}

json11::Json cabana::defaultWorkspace() {
  auto doc = blankWorkspace().object_items();
  auto pages = doc["pages"].array_items();
  auto page = pages[0].object_items();
  page["name"] = "CAN";
  page["widgets"] = json11::Json::array{"###MessagesPanel", "###CenterWidget", "###VideoPanel", "###ChartsWindow"};
  page["dock"] = json11::Json();
  pages[0] = page;
  doc["pages"] = pages;
  return doc;
}
