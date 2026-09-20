#pragma once

#include "tools/cabana/ui/chart/layout.h"

namespace cabana {
// Rebind all persisted source references, including timeline maps and chart signals.
inline json11::Json remapWorkspaceSource(const json11::Json &document, const std::string &old_id, const std::string &new_id) {
  using json11::Json;
  auto doc = document.object_items();
  Json::array sources, widgets;
  for (const auto &source : document["sources"].array_items()) {
    auto value = source.object_items();
    if (source["id"] == old_id) value["id"] = new_id;
    sources.push_back(value);
  }
  for (const auto &widget : document["widgets"].array_items()) {
    auto value = widget.object_items();
    if (widget["source"] == old_id) value["source"] = new_id;
    widgets.push_back(value);
  }
  doc["sources"] = sources;
  doc["widgets"] = widgets;
  auto timeline = document["timeline"].object_items();
  for (const char *key : {"selected", "linked_master", "loop_source"}) if (timeline[key] == old_id) timeline[key] = new_id;
  for (const char *key : {"offsets", "positions"}) {
    auto values = timeline[key].object_items();
    if (auto it = values.find(old_id); it != values.end()) {
      values[new_id] = it->second;
      values.erase(it);
    }
    timeline[key] = values;
  }
  Json::array linked;
  for (const auto &id : timeline["linked"].array_items()) linked.push_back(id == old_id ? Json(new_id) : id);
  timeline["linked"] = linked;
  doc["timeline"] = timeline;
  auto charts = document["charts"].object_items();
  auto remap_chart = [&](const Json &chart) {
    auto value = chart.object_items();
    Json::array signals;
    for (const auto &signal : chart["signals"].array_items()) {
      auto s = signal.object_items();
      if (signal["source"] == old_id) s["source"] = new_id;
      signals.push_back(s);
    }
    value["signals"] = signals;
    return Json(value);
  };
  if (charts["charts"].is_array()) {
    Json::array values;
    for (const auto &chart : charts["charts"].array_items()) values.push_back(remap_chart(chart));
    charts["charts"] = values;
  }
  if (charts["tabs"].is_array()) {
    Json::array tabs;
    for (const auto &tab : charts["tabs"].array_items()) {
      Json::array values;
      for (const auto &chart : tab.array_items()) values.push_back(remap_chart(chart));
      tabs.push_back(values);
    }
    charts["tabs"] = tabs;
  }
  doc["charts"] = charts;
  return doc;
}

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
  for (const auto &s : doc["sources"].array_items()) if (!s["inspector"].is_null()) {
    if (!s["inspector"].is_object() || !s["inspector"]["active"].is_string() || !s["inspector"]["messages"].is_array()) return false;
    for (const auto &id : s["inspector"]["messages"].array_items()) if (!id.is_string()) return false;
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
