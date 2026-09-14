#pragma once

#include <algorithm>
#include <cmath>
#include <deque>
#include <optional>
#include "tools/cabana/analysis/fields.h"

namespace cabana {
enum class Transform { None, Derivative, Integral, MovingAverage };
struct TransformSettings {
  Transform type = Transform::None;
  double scale = 1, offset = 0, time_offset = 0;
  // Zero selects actual elapsed time, as in PlotJuggler's FirstDerivative.
  double derivative_divisor = 0;
  int window = 10;
};

// Affine value adjustment, then analysis, then time offset. Each recomputation starts
// from fresh state. A non-finite input breaks continuity rather than bridging a gap.
inline Samples transformSamples(const Samples &input, const TransformSettings &settings) {
  Samples output;
  output.reserve(input.size());
  std::optional<Sample> previous;
  std::deque<double> window;
  double integral = 0, sum = 0;
  for (const auto &raw : input) {
    Sample p{raw.x, raw.y * settings.scale + settings.offset};
    if (!std::isfinite(p.x) || !std::isfinite(p.y)) {
      previous.reset(); window.clear(); sum = 0; integral = 0;
      continue;
    }
    Sample result = p;
    bool emit = true;
    switch (settings.type) {
      case Transform::Derivative: {
        const double divisor = settings.derivative_divisor == 0 && previous ? p.x - previous->x : settings.derivative_divisor;
        emit = previous.has_value() && divisor > 0;
        if (emit) result = {previous->x, (p.y - previous->y) / divisor};
        break;
      }
      case Transform::Integral:
        if (previous && p.x > previous->x) integral += (p.x - previous->x) * (p.y / 2 + previous->y / 2);
        result.y = integral;
        break;
      case Transform::MovingAverage:
        window.push_back(p.y); sum += p.y;
        if (window.size() > std::max(settings.window, 1)) { sum -= window.front(); window.pop_front(); }
        result.y = sum / window.size();
        break;
      case Transform::None: break;
    }
    previous = p;
    result.x += settings.time_offset;
    if (emit && std::isfinite(result.x) && std::isfinite(result.y)) output.push_back(result);
  }
  return output;
}
}
