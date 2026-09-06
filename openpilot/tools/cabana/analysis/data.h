#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>
#include <capnp/dynamic.h>
#include "openpilot/cereal/gen/cpp/log.capnp.h"

namespace cabana::analysis {
struct Sample { double time, value; };
struct Channel {
  std::vector<Sample> samples;
  std::map<int, std::string> labels;
  std::optional<double> at(double time) const;
};
struct LogLine {
  double time = 0, wall = 0;
  int level = 20;
  std::string source, message, context;
};
struct SentFrame { double time; uint32_t address; uint8_t bus; std::vector<uint8_t> bytes; };
struct Thumbnail { double time; std::vector<unsigned char> jpeg; };
struct Data {
  // Store a common monotonic clock; the workspace subtracts its route origin for display.
  std::map<std::string, Channel> channels;
  std::vector<SentFrame> sent_frames;
  std::vector<LogLine> logs;
  std::vector<Thumbnail> thumbnails;
  double first = 0, last = 0;
  uint64_t revision = 0;
  void append(cereal::Event::Reader event);
  void merge(Data batch);
  void trim(double before);
private:
  void visit(const std::string &path, capnp::DynamicValue::Reader value, double time, int depth = 0);
};
std::vector<Sample> transform(const Channel &source, double scale, double offset, bool derivative, double dt);
}  // namespace cabana::analysis
