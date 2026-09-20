#pragma once

#include "tools/cabana/ui/chart/layout.h"

namespace cabana {
inline bool validWorkspace(const json11::Json &doc) {
  if ((doc["cabana_workspace"] != 1 && doc["cabana_workspace"] != 2) || !doc["name"].is_string() ||
      doc["name"].string_value().empty() || !doc["ui"].is_string() || !chart::parseLayout(doc["charts"].dump())) return false;
  if (doc["cabana_workspace"] == 1) {
    for (const char *panel : {"messages", "logs", "charts", "video", "details", "playback"})
      if (!doc["panels"][panel].is_bool()) return false;
    return true;
  }
  if (!doc["sources"].is_array() || !doc["widgets"].is_array() || !doc["timeline"].is_object()) return false;
  std::set<std::string> sources, widgets;
  for (const auto &s : doc["sources"].array_items()) {
    if (!s["id"].is_string() || s["id"].string_value().empty() || !sources.insert(s["id"].string_value()).second ||
        !s["label"].is_string() || (!s["route"].is_null() && !s["route"].is_string()) ||
        (!s["data_dir"].is_null() && !s["data_dir"].is_string())) return false;
  }
  for (const auto &w : doc["widgets"].array_items()) {
    const auto kind = w["kind"].string_value();
    if (kind != "can" && kind != "logs" && kind != "inspector" && kind != "camera") return false;
    if (!sources.count(w["source"].string_value())) return false;
    if (kind == "camera") {
      if (!w["id"].is_string() || w["id"].string_value().empty() || !widgets.insert(w["id"].string_value()).second ||
          !w["crop"].is_bool() || !w["camera"].is_number() ||
          w["camera"].number_value() != w["camera"].int_value() || w["camera"].int_value() < 0 || w["camera"].int_value() > 2) return false;
    }
  }
  return true;
}
}  // namespace cabana
