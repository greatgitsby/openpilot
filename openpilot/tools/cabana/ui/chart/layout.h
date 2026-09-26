#pragma once

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <optional>

#include "json11/json11.hpp"
#include "tools/cabana/core/color.h"
#include "tools/cabana/core/message_id.h"
#include "tools/cabana/analysis/equations.h"
#include "tools/cabana/ui/chart/analysis.h"

namespace chart {
// {"cabana_layout": 4, "range": seconds, "charts": [chart, ...], "equations": [equation, ...]}
// chart: {"signals": [signal, ...]} with optional "id", "title", "type", "y_min" and "y_max".
// signal: a log field path or function name, or an object with "path" or "message" ("bus:ADDRESS") and "signal",
//   optional "source" (the current source when omitted), "color" ("#rrggbb", fields only; CAN signals use the DBC color)
//   and SIGNAL_DEFAULTS. Fields without a color take the next free palette color.
// equation: {"name", "source", "function"} with optional "globals" and "additional" inputs. Names cannot start with '/',
//   which is reserved for log fields.
// Defaults are omitted when saving.
inline const json11::Json::object SIGNAL_DEFAULTS{{"visible", true}, {"transform", 0}, {"scale", 1}, {"offset", 0}, {"window", 10}};

struct LayoutSignal {
  MessageId id;
  std::string name, path, source_id;
  TransformSettings transform;
  bool visible = true;
  std::optional<CabanaColor> color;
};
struct LayoutChart {
  std::string id, title;
  int type = 0;
  std::optional<double> y_min, y_max;
  std::vector<LayoutSignal> signals;
};
struct Layout {
  int range = 0;
  std::vector<LayoutChart> charts;
  std::vector<cabana::Equation> equations;
};

inline std::optional<Layout> parseLayout(const std::string &contents) {
  using json11::Json;
  std::string error;
  const auto doc = Json::parse(contents, error);
  if (doc["cabana_layout"] != 4 || !doc["charts"].is_array()) return std::nullopt;
  auto number = [](const Json &v) { return v.is_number() && std::isfinite(v.number_value()) ? std::optional(v.number_value()) : std::nullopt; };
  Layout layout{doc["range"].int_value()};
  for (const auto &c : doc["charts"].array_items()) {
    auto &chart = layout.charts.emplace_back(LayoutChart{c["id"].string_value(), c["title"].string_value(),
                                                         std::clamp(c["type"].int_value(), 0, 2), number(c["y_min"]), number(c["y_max"])});
    for (const auto &item : c["signals"].array_items()) {
      auto fields = item.is_string() ? Json::object{{"path", item}} : item.object_items();
      fields.insert(SIGNAL_DEFAULTS.begin(), SIGNAL_DEFAULTS.end());
      const Json s(fields);
      const auto id = MessageId::parse(s["message"].string_value());
      if (s["path"].string_value().empty() && (!id || s["signal"].string_value().empty())) return std::nullopt;
      std::optional<CabanaColor> color;
      if (const auto &hex = s["color"].string_value(); hex.size() == 7 && hex[0] == '#') {
        const auto rgb = std::strtoul(hex.c_str() + 1, nullptr, 16);
        color = CabanaColor(rgb >> 16 & 0xff, rgb >> 8 & 0xff, rgb & 0xff);
      }
      chart.signals.push_back({id.value_or(MessageId{}), s["signal"].string_value(), s["path"].string_value(), s["source"].string_value(),
                               {(Transform)std::clamp(s["transform"].int_value(), 0, 3), number(s["scale"]).value_or(1),
                                number(s["offset"]).value_or(0), std::clamp(s["window"].int_value(), 1, 100000)},
                               s["visible"].bool_value(), color});
    }
  }
  for (const auto &e : doc["equations"].array_items()) {
    auto &equation = layout.equations.emplace_back(cabana::Equation{e["name"].string_value(), e["source"].string_value(),
                                                                    e["globals"].string_value(), e["function"].string_value()});
    if (equation.name.empty() || equation.name[0] == '/' || equation.source.empty()) return std::nullopt;
    for (const auto &input : e["additional"].array_items()) equation.additional.push_back(input.string_value());
  }
  return layout;
}

inline std::string dumpLayout(const Layout &layout) {
  using json11::Json;
  Json::array charts, equations;
  for (const auto &c : layout.charts) {
    Json::array signals;
    for (const auto &s : c.signals) {
      Json::object signal{{"source", s.source_id}, {"visible", s.visible}, {"transform", (int)s.transform.type},
                          {"scale", s.transform.scale}, {"offset", s.transform.offset}, {"window", s.transform.window}};
      for (const auto &[key, value] : SIGNAL_DEFAULTS) if (signal.at(key) == value) signal.erase(key);
      if (s.source_id.empty()) signal.erase("source");
      if (s.color) {
        char hex[8];
        snprintf(hex, sizeof(hex), "#%02x%02x%02x", s.color->r, s.color->g, s.color->b);
        signal["color"] = hex;
      }
      if (!s.path.empty() && signal.empty()) { signals.push_back(s.path); continue; }
      if (s.path.empty()) { signal["message"] = s.id.toString(); signal["signal"] = s.name; }
      else signal["path"] = s.path;
      signals.push_back(signal);
    }
    Json::object chart{{"signals", signals}};
    if (!c.id.empty()) chart["id"] = c.id;
    if (!c.title.empty()) chart["title"] = c.title;
    if (c.type) chart["type"] = c.type;
    if (c.y_min) chart["y_min"] = *c.y_min;
    if (c.y_max) chart["y_max"] = *c.y_max;
    charts.push_back(chart);
  }
  for (const auto &e : layout.equations) {
    Json::object equation{{"name", e.name}, {"source", e.source}, {"function", e.function}};
    if (!e.globals.empty()) equation["globals"] = e.globals;
    if (!e.additional.empty()) equation["additional"] = Json::array(e.additional.begin(), e.additional.end());
    equations.push_back(equation);
  }
  Json::object doc{{"cabana_layout", 4}, {"range", layout.range}, {"charts", charts}};
  if (!equations.empty()) doc["equations"] = equations;
  return Json(doc).dump();
}
}  // namespace chart
