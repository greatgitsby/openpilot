#pragma once
#include <string>
#include <vector>
#include "json11/json11.hpp"

namespace cabana::analysis {
struct Curve {
  std::string name, label, color = "#36a9e1";
  bool visible = true, derivative = false;
  double scale = 1, offset = 0, dt = 0;
};
struct Pane {
  std::string title = "Plot", kind = "plot", camera = "road";
  std::vector<Curve> curves;
  bool y_min_set = false, y_max_set = false;
  double y_min = 0, y_max = 1;
  int style = 0;
  std::string split;
  std::vector<Pane> children;
  std::vector<double> sizes;
};
struct Tab { std::string name = "Analysis"; Pane root; };
struct Formula {
  std::string name, source, globals, code = "return value";
  std::vector<std::string> additional;
};
struct Layout {
  std::vector<Tab> tabs = {Tab{}};
  std::vector<Formula> formulas;
  int active = 0;
  bool range_set = false;
  double x_min = 0, x_max = 1;
  json11::Json json() const;
  static Layout parse(const json11::Json &document);
};
}  // namespace cabana::analysis
