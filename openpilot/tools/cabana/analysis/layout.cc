#include "tools/cabana/analysis/layout.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <functional>

namespace cabana::analysis {
using J = json11::Json;
namespace {
double number(const J &j, double fallback) { return j.is_number() && std::isfinite(j.number_value()) ? j.number_value() : fallback; }
J paneJson(const Pane &p) {
  J::array curves, children, sizes;
  for (auto &c : p.curves) curves.push_back(J::object{{"name", c.name}, {"label", c.label}, {"color", c.color},
    {"visible", c.visible}, {"derivative", c.derivative}, {"value_scale", c.scale}, {"value_offset", c.offset}, {"derivative_dt", c.dt}});
  for (auto &child : p.children) children.push_back(paneJson(child));
  for (double s : p.sizes) sizes.push_back(s);
  return J::object{{"title", p.title}, {"kind", p.kind}, {"camera_view", p.camera}, {"curves", curves}, {"split", p.split},
    {"children", children}, {"sizes", sizes}, {"style", p.style}, {"limitY", J::object{{"min", p.y_min_set ? J(p.y_min) : J()}, {"max", p.y_max_set ? J(p.y_max) : J()}}}};
}
Pane readPane(const J &j, int depth) {
  if (!j.is_object() || depth > 24) throw std::runtime_error("Invalid pane or excessive split depth");
  if (j["children"].array_items().size() > 64 || j["curves"].array_items().size() > 256) throw std::runtime_error("Pane exceeds 64 children or 256 curves");
  Pane p;
  if (j["title"].is_string()) p.title = j["title"].string_value();
  if (j["kind"].is_string()) p.kind = j["kind"].string_value();
  if (j["camera_view"].is_string()) p.camera = j["camera_view"].string_value();
  p.split = j["split"].string_value();
  p.style = std::clamp(j["style"].int_value(), 0, 2);
  const J &limits = j["y_limits"].is_object() ? j["y_limits"] : j["limitY"];
  p.y_min_set = limits["min"].is_number(); p.y_max_set = limits["max"].is_number();
  p.y_min = number(limits["min"], 0); p.y_max = number(limits["max"], 1);
  if (p.y_min_set && p.y_max_set && p.y_min >= p.y_max) throw std::runtime_error("Y minimum must be below maximum");
  for (auto &v : j["curves"].array_items()) {
    Curve c;
    c.name = v["name"].string_value(); c.label = v["label"].string_value();
    if (c.name.empty()) throw std::runtime_error("Curve has no source name");
    if (v["color"].is_string()) c.color = v["color"].string_value();
    c.visible = !v["visible"].is_bool() || v["visible"].bool_value();
    c.derivative = v["derivative"].bool_value() || v["transform"].string_value() == "derivative";
    c.scale = number(v["value_scale"], number(v["scale"], 1)); c.offset = number(v["value_offset"], number(v["offset"], 0)); c.dt = number(v["derivative_dt"], 0);
    p.curves.push_back(c);
  }
  for (auto &v : j["children"].array_items()) p.children.push_back(readPane(v, depth + 1));
  if (!p.children.empty() && p.split != "horizontal" && p.split != "vertical") throw std::runtime_error("Unknown split direction");
  for (auto &v : j["sizes"].array_items()) p.sizes.push_back(std::max(0.05, number(v, 1)));
  if (p.sizes.size() != p.children.size()) p.sizes.assign(p.children.size(), 1.0);
  return p;
}
}
J Layout::json() const {
  J::array t, f;
  for (auto &tab : tabs) t.push_back(J::object{{"name", tab.name}, {"root", paneJson(tab.root)}});
  for (auto &formula : formulas) f.push_back(J::object{{"name", formula.name}, {"linked_source", formula.source},
    {"additional_sources", formula.additional}, {"globals_code", formula.globals}, {"function_code", formula.code}});
  return J::object{{"version", 1}, {"time_range", range_set ? J(J::array{x_min, x_max}) : J()}, {"current_tab_index", active}, {"tabs", t}, {"formulas", f}};
}
Layout Layout::parse(const J &j) {
  if (!j.is_object() || j["tabs"].array_items().empty()) throw std::runtime_error("Layout must contain tabs");
  if (j["tabs"].array_items().size() > 64 || j["formulas"].array_items().size() > 256) throw std::runtime_error("Layout exceeds 64 tabs or 256 formulas");
  size_t nodes = 0;
  std::function<void(const J &, int)> validate = [&](const J &node, int depth) {
    if (++nodes > 1024 || depth > 24) throw std::runtime_error("Layout is too deeply nested or has too many panes");
    for (auto &child : node["children"].array_items()) validate(child, depth + 1);
  };
  for (auto &tab : j["tabs"].array_items()) validate(tab["root"], 0);
  Layout result; result.tabs.clear();
  for (auto &tab : j["tabs"].array_items()) result.tabs.push_back({tab["name"].string_value(), readPane(tab["root"], 0)});
  if (j["time_range"].is_array()) {
    const auto &range = j["time_range"].array_items();
    if (range.size() != 2 || !range[0].is_number() || !range[1].is_number() || !std::isfinite(range[0].number_value()) ||
        !std::isfinite(range[1].number_value()) || range[0].number_value() >= range[1].number_value()) throw std::runtime_error("Invalid time range");
    result.range_set = true; result.x_min = range[0].number_value(); result.x_max = range[1].number_value();
  }
  result.active = std::clamp(j["current_tab_index"].int_value(), 0, int(result.tabs.size()) - 1);
  for (auto &v : j["formulas"].array_items()) {
    Formula f{v["name"].string_value(), v["linked_source"].string_value(), v["globals_code"].string_value(), v["function_code"].string_value(), {}};
    for (auto &source : v["additional_sources"].array_items()) f.additional.push_back(source.string_value());
    result.formulas.push_back(f);
  }
  std::function<void(const J &)> inline_formulas = [&](const J &node) {
    if (!result.range_set && node["range"]["left"].is_number() && node["range"]["right"].is_number()) {
      double left = node["range"]["left"].number_value(), right = node["range"]["right"].number_value();
      if (std::isfinite(left) && std::isfinite(right) && left < right) { result.range_set = true; result.x_min = left; result.x_max = right; }
    }
    for (auto &curve : node["curves"].array_items()) {
      const auto &definition = curve["custom_python"];
      if (definition.is_object()) {
        Formula f{curve["name"].string_value(), definition["linked_source"].string_value(), definition["globals_code"].string_value(), definition["function_code"].string_value(), {}};
        for (auto &source : definition["additional_sources"].array_items()) f.additional.push_back(source.string_value());
        if (std::none_of(result.formulas.begin(), result.formulas.end(), [&](auto &existing) { return existing.name == f.name; })) result.formulas.push_back(f);
      }
    }
    for (auto &child : node["children"].array_items()) inline_formulas(child);
  };
  for (auto &tab : j["tabs"].array_items()) inline_formulas(tab["root"]);
  return result;
}
}  // namespace cabana::analysis
