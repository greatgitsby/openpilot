#include "tools/cabana/streams/logfilestream.h"
#include "common/timing.h"

bool LogFileStream::load(const std::string &path) {
  LogReader reader;
  if (!reader.load(path) || reader.events.empty()) return false;
  path_ = path;
  origin_ = reader.events.front().mono_time;
  std::vector<const CanEvent *> events;
  for (const auto &entry : reader.events) {
    if (entry.eidx_segnum >= 0) continue;
    capnp::FlatArrayMessageReader message(entry.data);
    auto event = message.getRoot<cereal::Event>();
    analysis_data.append(event);
    if (event.which() == cereal::Event::CAN) {
      for (auto frame : event.getCan()) events.push_back(newEvent(entry.mono_time, frame));
    }
  }
  mergeEvents(events);
  duration_ = (reader.events.back().mono_time - origin_) * 1e-9;
  return true;
}
void LogFileStream::start() { last_tick_ = seconds_since_boot(); seekTo(0); }
void LogFileStream::pause(bool value) { paused_ = value; last_tick_ = seconds_since_boot(); value ? paused() : resume(); }
void LogFileStream::seekTo(double time) { current_sec_ = std::clamp(time, 0.0, duration_); seekedTo(current_sec_); }
void LogFileStream::tick() {
  double now = seconds_since_boot();
  if (!paused_) {
    double next = current_sec_ + (now - last_tick_) * speed_;
    if (time_range_ && next > time_range_->second) next = time_range_->first;
    seekTo(next);
    if (next >= duration_) pause(true);
  }
  last_tick_ = now;
}
