#pragma once
#include "tools/cabana/streams/abstractstream.h"
#include "tools/replay/logreader.h"

// Direct log files use the same analysis and CAN views as a route replay.
class LogFileStream : public AbstractStream {
public:
  bool load(const std::string &path);
  void start() override;
  void tick();
  bool liveStreaming() const override { return false; }
  std::string routeName() const override { return path_; }
  uint64_t beginMonoTime() const override { return origin_; }
  double maxSeconds() const override { return duration_; }
  bool isPaused() const override { return paused_; }
  void pause(bool value) override;
  void seekTo(double time) override;
  void setSpeed(float value) override { speed_ = value; }
  double getSpeed() override { return speed_; }
private:
  std::string path_;
  uint64_t origin_ = 0;
  double duration_ = 0, speed_ = 1, last_tick_ = 0;
  bool paused_ = true;
};
