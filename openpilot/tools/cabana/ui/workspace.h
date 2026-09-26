#pragma once

#include <algorithm>
#include <set>
#include <string>

#include "tools/cabana/ui/chart/layout.h"
#include "tools/replay/route.h"

namespace cabana {
inline bool isBuiltinWorkspace(const json11::Json &document) {
  return !document["builtin"].string_value().empty();
}

// A copy for saving or sharing; built-in identity stays in this session.
inline json11::Json customWorkspace(const json11::Json &document) {
  auto custom = document.object_items();
  custom.erase("builtin");
  custom.erase("builtin_initialized");
  return custom;
}

// Only custom workspaces persist. A built-in selection is remembered by its key.
inline json11::Json workspaceLibrary(const json11::Json::array &workspaces, int active) {
  json11::Json::array saved;
  int selected = -1;
  for (int i = 0; i < (int)workspaces.size(); ++i) {
    if (isBuiltinWorkspace(workspaces[i])) continue;
    if (i == active) selected = saved.size();
    saved.push_back(workspaces[i]);
  }
  const bool builtin = active >= 0 && active < (int)workspaces.size() && isBuiltinWorkspace(workspaces[active]);
  return json11::Json::object{{"active", selected}, {"active_builtin", builtin ? workspaces[active]["builtin"] : json11::Json("")}, {"workspaces", saved}};
}

inline std::string savedSourceRoute(const json11::Json &source) {
  const auto &route = source["route"].string_value();
  return route.empty() ? std::string() : Route::parseRoute(route).str;
}

// Rebind every reference to a source: its slot, widgets, timeline maps and lists, and chart signals. When
// `to` already exists (merging a duplicate slot), its entries win over the remapped ones. User text is kept.
inline json11::Json remapWorkspaceSource(const json11::Json &value, const std::string &from, const std::string &to) {
  using json11::Json;
  if (from == to) return value;
  if (value.is_string()) return value == Json(from) ? Json(to) : value;
  if (value.is_array()) {
    const auto &items = value.array_items();
    const auto is = [](const Json &item, const std::string &id) { return item == Json(id) || (item.is_object() && item["id"] == Json(id)); };
    const bool merging = std::any_of(items.begin(), items.end(), [&](const Json &item) { return is(item, to); });
    Json::array result;
    for (const auto &item : items) if (!merging || !is(item, from)) result.push_back(remapWorkspaceSource(item, from, to));
    return result;
  }
  if (!value.is_object()) return value;
  Json::object result;
  for (const auto &[key, item] : value.object_items()) {
    if (key == from && value.object_items().count(to)) continue;
    const bool text = key == "label" || key == "name" || key == "title";
    result[key == from ? to : key] = text ? item : remapWorkspaceSource(item, from, to);
  }
  return result;
}

inline bool validWorkspace(const json11::Json &doc) {
  if (doc["cabana_workspace"] != 2 || doc["name"].string_value().empty() || !doc["ui"].is_string() || !doc["sources"].is_array() ||
      !doc["widgets"].is_array() || !doc["timeline"].is_object() || !chart::parseLayout(doc["charts"].dump())) return false;
  std::set<std::string> sources, cameras;
  for (const auto &source : doc["sources"].array_items()) {
    if (source["id"].string_value().empty() || !sources.insert(source["id"].string_value()).second) return false;
  }
  for (const auto &widget : doc["widgets"].array_items()) {
    if (!sources.count(widget["source"].string_value())) return false;
    if (widget["kind"] == "camera" && (widget["id"].string_value().empty() || !cameras.insert(widget["id"].string_value()).second ||
                                       widget["camera"].int_value() < 0 || widget["camera"].int_value() > 2)) return false;
  }
  return true;
}
}  // namespace cabana
