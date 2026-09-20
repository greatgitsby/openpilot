#pragma once

#include <algorithm>
#include <cmath>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace cabana::playback {
// Keep a linked group's clock independent of selection in other groups.
inline std::string linkedMaster(const std::string &current, const std::string &selected,
                                const std::vector<std::string> &members) {
  const auto contains = [&](const std::string &id) { return std::find(members.begin(), members.end(), id) != members.end(); };
  if (contains(current)) return current;
  if (contains(selected)) return selected;
  return members.empty() ? "" : members.front();
}

// Intersect the participating sources' ranges, expressed in workspace time.
inline std::optional<std::pair<double, double>> sharedRange(const std::vector<std::pair<double, double>> &ranges) {
  if (ranges.empty()) return std::nullopt;
  auto result = ranges.front();
  for (const auto &[begin, end] : ranges) {
    if (!std::isfinite(begin) || !std::isfinite(end) || begin > end) return std::nullopt;
    result.first = std::max(result.first, begin);
    result.second = std::min(result.second, end);
  }
  return result.first <= result.second ? std::make_optional(result) : std::nullopt;
}

inline std::optional<std::pair<double, double>> loopRange(double start, double end, std::pair<double, double> available) {
  if (!std::isfinite(start) || !std::isfinite(end) || end <= start) return std::nullopt;
  auto range = sharedRange({{start, end}, available});
  return range && range->second - range->first >= 0.001 ? range : std::nullopt;
}
}  // namespace cabana::playback
