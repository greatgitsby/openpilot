#include <cmath>
#include <random>
#include <filesystem>
#include <fstream>
#include "common/tests/native_test.h"
#include "tools/cabana/analysis/data.h"
#include "tools/cabana/analysis/layout.h"
#include "tools/cabana/analysis/python.h"
#include <capnp/message.h>

using namespace cabana::analysis;
using J = json11::Json;

void tests(const std::filesystem::path &cabana) {
  Data data;
  for (int i = 0; i < 1000; ++i) {
    capnp::MallocMessageBuilder builder;
    auto event = builder.initRoot<cereal::Event>();
    event.setLogMonoTime(1000000000ULL + i * 10000000ULL);
    auto car = event.initCarState(); car.setVEgo(i * 0.02); car.setGearShifter(cereal::CarState::GearShifter::DRIVE);
    data.append(event.asReader());
  }
  auto &speed = data.channels.at("/carState/vEgo");
  REQUIRE(speed.samples.size() == 1000);
  REQUIRE(!speed.at(0)); REQUIRE(std::abs(*speed.at(1.505) - 1.0) < 1e-5);
  REQUIRE(!data.channels.at("/carState/gearShifter").labels.empty());
  auto derivative = transform(speed, 1, 0, true, 0);
  REQUIRE(derivative.size() == 999); REQUIRE(std::abs(derivative.front().value - 2) < 1e-5);
  REQUIRE(derivative.front().time == speed.samples.front().time);
  Channel duplicate; duplicate.samples = {{0, 1}, {0, 2}, {2, 6}};
  REQUIRE(transform(duplicate, 1, 0, true, 0).size() == 1);
  REQUIRE(transform(duplicate, 2, 5, true, 1)[1].value == 13);
  data.trim(8); REQUIRE(data.channels.at("/carState/vEgo").samples.front().time >= 8);
  REQUIRE(data.channels.at("/carState/vEgo").samples.size() <= 300);

  Data ordered;
  for (int i : {2, 0, 1}) {
    Data batch;
    capnp::MallocMessageBuilder builder; auto event = builder.initRoot<cereal::Event>();
    event.setLogMonoTime(1000000000ULL * (i + 1)); event.initCarState().setVEgo(i);
    batch.append(event.asReader()); ordered.merge(std::move(batch));
  }
  auto &points = ordered.channels.at("/carState/vEgo").samples;
  REQUIRE(points.size() == 3); REQUIRE(points[0].value == 0); REQUIRE(points[2].value == 2);

  Layout layout;
  layout.tabs[0].root.curves.push_back(Curve{.name = "/carState/vEgo", .derivative = true, .scale = 3.6});
  layout.formulas.push_back(Formula{"double", "/carState/vEgo", "", "return value * 2", {}});
  auto restored = Layout::parse(layout.json()); REQUIRE(restored.json().dump() == layout.json().dump());
  for (auto malformed : std::vector<J>{J(), J::object{}, J::object{{"tabs", J::array{}}}, J::object{{"tabs", J::array{J::object{{"root", J::object{{"curves", J::array{J::object{}}}}}}}}}}) {
    bool failed = false; try { Layout::parse(malformed); } catch (const std::exception &) { failed = true; }
    REQUIRE(failed);
  }

  for (const auto &directory : {cabana / "layouts", cabana.parent_path() / "jotpluggler/layouts"}) {
    for (const auto &entry : std::filesystem::directory_iterator(directory)) {
      if (entry.path().extension() != ".json") continue;
      std::ifstream file(entry.path());
      std::string contents{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()}, error;
      auto imported = Layout::parse(J::parse(contents, error));
      REQUIRE(error.empty());
      REQUIRE(Layout::parse(imported.json()).json().dump() == imported.json().dump());
    }
  }

  // Exercise ordered batch merging and retention at streaming scale.
  Data live;
  for (int batch_number = 0; batch_number < 100; ++batch_number) {
    Data batch;
    for (int i = 0; i < 1000; ++i) {
      capnp::MallocMessageBuilder builder; auto event = builder.initRoot<cereal::Event>();
      event.setLogMonoTime(1000000000ULL + (batch_number * 1000ULL + i) * 1000000ULL);
      event.initCarState().setVEgo(i); batch.append(event.asReader());
    }
    live.merge(std::move(batch)); live.trim(live.last - 2);
    REQUIRE(live.channels.at("/carState/vEgo").samples.size() <= 2001);
  }
}
int main(int argc, char **argv) { return run_native_test([&]() { tests(std::filesystem::absolute(argv[0]).parent_path().parent_path()); }); }
