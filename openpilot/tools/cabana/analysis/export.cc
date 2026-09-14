#include "tools/cabana/analysis/export.h"
#include <fstream>
#include <iomanip>
#include <stdexcept>

namespace cabana {
void exportVisibleCsv(const std::string &path, const Fields &series, double first, double last) {
  std::ofstream output(path);
  output << "time,series,value\n" << std::setprecision(17);
  for (const auto &[name, samples] : series) {
    std::string escaped;
    for (char c : name) { escaped += c; if (c == '"') escaped += '"'; }
    for (const auto &point : samples) if (point.x >= first && point.x <= last) {
      output << point.x << ",\"" << escaped << "\"," << point.y << '\n';
    }
  }
  output.flush();
  if (!output) throw std::runtime_error("Could not write " + path);
}
}
