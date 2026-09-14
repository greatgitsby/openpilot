#include "common/tests/native_test.h"
#include "tools/cabana/analysis/transforms.h"
#include "tools/cabana/analysis/equations.h"

void test_analysis() {
  using namespace cabana;
  const Samples input{{2, 3}, {4, 7}, {7, 16}};
  auto derivative = transformSamples(input, {.type = Transform::Derivative});
  REQUIRE(derivative.size() == 2);
  REQUIRE(derivative[0].x == 2 && derivative[0].y == 2);
  REQUIRE(derivative[1].x == 4 && derivative[1].y == 3);
  derivative = transformSamples(input, {.type = Transform::Derivative, .derivative_divisor = 1});
  REQUIRE(derivative[0].x == 2 && derivative[0].y == 4);
  REQUIRE(derivative[1].x == 4 && derivative[1].y == 9);
  REQUIRE(transformSamples({{1, 2}, {1, 4}}, {.type = Transform::Derivative}).empty());
  REQUIRE(transformSamples(input, {.type = Transform::Derivative, .derivative_divisor = -1}).empty());
  auto scaled = transformSamples(input, {.scale = 2, .offset = -3, .time_offset = 5});
  REQUIRE(scaled[0].x == 7 && scaled[0].y == 3);
  REQUIRE(scaled[2].x == 12 && scaled[2].y == 29);
  auto integral = transformSamples(input, {.type = Transform::Integral});
  REQUIRE(integral[0].y == 0 && integral[1].y == 10 && integral[2].y == 44.5);
  auto average = transformSamples(input, {.type = Transform::MovingAverage, .window = 2});
  REQUIRE(average[0].y == 3 && average[1].y == 5 && average[2].y == 11.5);
  REQUIRE(transformSamples({}, {}).empty());
  const double nan = std::numeric_limits<double>::quiet_NaN();
  const auto gaps = transformSamples({{1, 1}, {2, nan}, {3, 3}, {4, 7}}, {.type = Transform::Derivative});
  REQUIRE(gaps.size() == 1 && gaps[0].x == 3 && gaps[0].y == 4);
  const auto duplicate = transformSamples({{1, 1}, {1, 4}}, {.type = Transform::Derivative, .derivative_divisor = 1});
  REQUIRE(duplicate.size() == 1 && duplicate[0].x == 1 && duplicate[0].y == 3);
  REQUIRE(nearestValue(input, -1) == 3);
  REQUIRE(nearestValue(input, 3) == 7);
  REQUIRE(nearestValue(input, 100) == 16);
  FieldsSnapshot fields{{"speed", std::make_shared<const Samples>(input)}};
  Equation equation{"sum", "speed", "total = 0", "global total\ntotal += value\nreturn time + 1, total", {}};
  auto evaluated = evaluateEquation(equation, fields);
  REQUIRE(evaluated.size() == 3 && evaluated[2].x == 8 && evaluated[2].y == 26);
  REQUIRE(evaluateEquation(equation, fields)[2].y == 26);
  Fields earlier{{"speed", {{0, 1}}}};
  prepareFieldsMerge(fields, earlier);
  REQUIRE(earlier["speed"].size() == 4 && earlier["speed"][0].x == 0 && earlier["speed"][3].x == 7);
}
int main() { return run_native_test(test_analysis); }
