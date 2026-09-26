#pragma once

#include <algorithm>
#include <deque>
#include <memory>
#include <set>
#include <thread>

#include "tools/cabana/streams/abstractstream.h"
#include "tools/replay/replay.h"

class ReplayStream : public AbstractStream {
public:
  ReplayStream();
  ~ReplayStream();
  void start() override;
  // Worker loaders report failures by exception; UI callers receive error().
  bool loadRoute(const std::string &route, const std::string &data_dir, uint32_t replay_flags = REPLAY_FLAG_NONE, bool auto_source = false);
  bool eventFilter(const Event *event);
  void seekTo(double ts) override { replay->seekTo(std::max(double(0), ts), false); }
  bool liveStreaming() const override { return false; }
  inline std::string routeName() const override { return replay->route().name(); }
  inline std::string carFingerprint() const override { return replay->carFingerprint(); }
  double currentSec() const override { return replay ? replay->currentSeconds() : current_sec_; }
  double minSeconds() const override { return replay->minSeconds(); }
  double maxSeconds() const override;
  inline std::chrono::system_clock::time_point beginDateTime() const override {
    return std::chrono::system_clock::from_time_t(replay->routeDateTime());
  }
  inline uint64_t beginMonoTime() const override { return replay->routeStartNanos(); }
  inline void setSpeed(float speed) override { replay->setSpeed(speed); }
  double getSpeed() override { return replay ? replay->getSpeed() : 1.0; }
  inline Replay *getReplay() const { return replay.get(); }
  inline bool isPaused() const override { return replay->isPaused(); }
  void pause(bool pause) override;
  const std::string &cameraEndpoint() const { return camera_endpoint_; }
  const std::string &routeReference() const { return route_reference_; }
  const std::string &dataDirectory() const { return data_directory_; }
  std::set<CameraType> availableCameras() const;
  std::optional<double> nextFrameTime(CameraType camera, double relative_sec, bool forward) const;

  // invoked on the main thread
  Observable<std::shared_ptr<LogReader>> qLogLoaded;

private:
  void mergeSegments();
  void indexFields();
  std::thread fields_thread_;
  std::mutex fields_mutex_;
  std::condition_variable fields_cv_;
  std::deque<std::shared_ptr<Segment>> pending_segments_;
  std::atomic<bool> stopping_ = false;
  std::unique_ptr<Replay> replay = nullptr;
  Connection settings_connection_;
  std::set<int> processed_segments;
  std::string camera_endpoint_;
  std::string route_reference_, data_directory_;
  double previous_update_ts_ = 0;
  mutable std::atomic<double> known_end_ = -1;
};
