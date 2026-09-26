#include "tools/cabana/streams/replaystream.h"

#include <string>
#include <stdexcept>

#include "common/timing.h"
#include "common/util.h"
#include "tools/cabana/analysis/logfields.h"
#include "tools/cabana/settings.h"
#include "tools/cabana/core/source.h"

ReplayStream::ReplayStream() {
  static std::once_flag environment_initialized;
  std::call_once(environment_initialized, []() {
    unsetenv("ZMQ");
    setenv("COMMA_CACHE", "/tmp/comma_download_cache", 0);
  });

  // Each camera publisher gets its own socket name. OPENPILOT_PREFIX is a
  // process-wide environment variable and cannot isolate concurrent routes.
  camera_endpoint_ = "cabana_" + util::random_string(15);

  fields_thread_ = std::thread([this]() { indexFields(); });
}

void ReplayStream::start() {
  SourceScope scope(this);
  settings_connection_ = settings.changed.connect([this]() {
    if (replay) replay->setSegmentCacheLimit(settings.max_cached_minutes);
  });
  replay->start();
}

ReplayStream::~ReplayStream() {
  {
    std::lock_guard lock(fields_mutex_);
    stopping_ = true;
  }
  cancelWaits();
  if (replay) replay->stop();
  fields_cv_.notify_one();
  if (fields_thread_.joinable()) fields_thread_.join();
}

// CAN history must be ready for seeking. Cereal indexing can finish in the background.
void ReplayStream::mergeSegments() {
  auto event_data = replay->getEventData();
  for (const auto &[n, seg] : event_data->segments) {
    if (stopping_) return;
    if (!processed_segments.count(n)) {
      processed_segments.insert(n);

      std::vector<const CanEvent *> new_events;
      new_events.reserve(seg->log->events.size());
      MessageEventsMap msg_events;
      std::array<std::vector<double>, MAX_CAMERAS> new_frame_times;
      for (const Event &e : seg->log->events) {
        if (stopping_) return;
        int camera = -1;
        switch (e.which) {
          case cereal::Event::Which::NARROW_ROAD_ENCODE_IDX: camera = NarrowRoadCam; break;
          case cereal::Event::Which::CABIN_ENCODE_IDX: camera = CabinCam; break;
          case cereal::Event::Which::WIDE_ROAD_ENCODE_IDX: camera = WideRoadCam; break;
          default: break;
        }
        // LogReader adds a synthetic encode event at the frame SOF.
        // The original log event can arrive later and is not another frame.
        if (camera >= 0 && e.eidx_segnum != -1) new_frame_times[camera].push_back(toSeconds(e.mono_time));
        if (e.which == cereal::Event::Which::CAN) {
          capnp::FlatArrayMessageReader reader(e.data);
          auto event = reader.getRoot<cereal::Event>();
          for (const auto &c : event.getCan()) {
            const CanEvent *ce = newEvent(e.mono_time, c);
            new_events.push_back(ce);
            msg_events[{.source = ce->src, .address = ce->address}].push_back(ce);
          }
        }
      }
      postToMainThreadAndWait([&]() {
        for (int camera = 0; camera < MAX_CAMERAS; ++camera) {
          auto &times = frame_times_[camera];
          const auto &added = new_frame_times[camera];
          const auto old_size = times.size();
          times.insert(times.end(), added.begin(), added.end());
          std::inplace_merge(times.begin(), times.begin() + old_size, times.end());
          times.erase(std::unique(times.begin(), times.end()), times.end());
        }
        insertEvents(new_events, msg_events);
      });
      {
        std::lock_guard lock(fields_mutex_);
        pending_segments_.push_back(seg);
      }
      fields_cv_.notify_one();
    }
  }
}

void ReplayStream::indexFields() {
  while (true) {
    std::unique_lock lock(fields_mutex_);
    fields_cv_.wait(lock, [this]() { return stopping_ || !pending_segments_.empty(); });
    if (stopping_) return;
    auto segment = std::move(pending_segments_.front());
    pending_segments_.pop_front();
    lock.unlock();

    auto fields_batch = cabana::extractLogFields(*segment->log, stopping_);
    if (stopping_) return;
    // This worker is the only writer. Retired snapshots are freed here, off the UI thread.
    cabana::prepareFieldsMerge(fields, fields_batch);
    auto next = fields;
    for (auto &[path, samples] : fields_batch) next[path] = std::make_shared<const cabana::Samples>(std::move(samples));
    postToMainThreadAndWait([&]() {
      fields.swap(next);
      fieldsChanged();
    });
  }
}

bool ReplayStream::loadRoute(const std::string &route, const std::string &data_dir, uint32_t replay_flags, bool auto_source) {
  route_reference_ = route;
  data_directory_ = data_dir;
  replay_flags |= REPLAY_FLAG_CABIN_CAMERA | REPLAY_FLAG_WIDE_ROAD;
  replay.reset(new Replay(route, {},
                          {}, nullptr, replay_flags, data_dir, auto_source, camera_endpoint_));
  replay->setSegmentCacheLimit(settings.max_cached_minutes);
  replay->installEventFilter([this](const Event *event) { return eventFilter(event); });

  // replay callbacks arrive on replay threads
  replay->onSeeking = [this](double sec) { postToMainThread([this, sec]() { seeking(sec); }); };
  replay->onSeekedTo = [this](double sec) {
    postToMainThread([this, sec]() { seekedTo(sec); });
    waitForSeekFinshed();
  };
  replay->onQLogLoaded = [this](std::shared_ptr<LogReader> qlog) { postToMainThread([this, qlog]() { qLogLoaded(qlog); }); };
  replay->onSegmentsMerged = [this]() { mergeSegments(); };

  bool success = replay->load();
  if (!success) {
    std::string message;
    if (replay->lastRouteError() == RouteLoadError::Unauthorized) {
      auto auth_content = util::read_file(util::getenv("HOME") + "/.comma/auth.json");
      if (auth_content.empty()) {
        message = "Authentication Required. Please run the following command to authenticate:\n\n"
                  "python3 openpilot/tools/lib/auth.py\n\n"
                  "This will grant access to routes from your comma account.";
      } else {
        message = "Access Denied. You do not have permission to access route:\n\n" + route + "\n\n"
                  "This is likely a private route.";
      }
    } else if (replay->lastRouteError() == RouteLoadError::NetworkError) {
      message = "Unable to load the route:\n\n " + route + ".\n\nPlease check your network connection and try again.";
    } else if (replay->lastRouteError() == RouteLoadError::FileNotFound) {
      message = "The specified route could not be found:\n\n " + route + ".\n\nPlease check the route name and try again.";
    } else {
      message = "Failed to load route: '" + route + "'";
    }
    if (utils::isMainThread()) {
      SourceScope scope(this);
      error(message);
    } else {
      // Loading precedes UI adoption. The startup loader owns exception delivery
      // to the main thread; never invoke UI observers or switch globals here.
      throw std::runtime_error(message);
    }
  }
  return success;
}

bool ReplayStream::eventFilter(const Event *event) {
  if (event->which == cereal::Event::Which::CAN) {
    double current_sec = toSeconds(event->mono_time);
    capnp::FlatArrayMessageReader reader(event->data);
    auto e = reader.getRoot<cereal::Event>();
    for (const auto &c : e.getCan()) {
      MessageId id = {.source = c.getSrc(), .address = c.getAddress()};
      const auto dat = c.getDat();
      updateEvent(id, current_sec, (const uint8_t*)dat.begin(), dat.size());
    }
  }

  double ts = millis_since_boot();
  if ((ts - previous_update_ts_) > (1000.0 / STREAM_UPDATE_FPS)) {
    const double sec = toSeconds(event->mono_time);
    postToMainThread([this, sec]() { current_sec_ = sec; updateLastMessages(); });
    previous_update_ts_ = ts;
  }
  return true;
}

void ReplayStream::pause(bool pause) {
  SourceScope scope(this);
  replay->pause(pause);
  pause ? paused() : resume();
}

std::set<CameraType> ReplayStream::availableCameras() const {
  std::set<CameraType> cameras;
  if (!replay) return cameras;
  for (const auto &[number, segment] : replay->route().segments()) {
    if (!segment.narrow_road_cam.empty() || !segment.qcamera.empty()) cameras.insert(NarrowRoadCam);
    if (!segment.cabin_cam.empty()) cameras.insert(CabinCam);
    if (!segment.wide_road_cam.empty()) cameras.insert(WideRoadCam);
  }
  return cameras;
}

std::optional<double> ReplayStream::nextFrameTime(CameraType camera, double relative_sec, bool forward) const {
  if (camera < 0 || camera >= MAX_CAMERAS) return std::nullopt;
  const auto &times = frame_times_[camera];
  constexpr double tolerance = 0.001;
  if (forward) {
    auto it = std::upper_bound(times.begin(), times.end(), relative_sec + tolerance);
    if (it != times.end()) return *it;
  } else {
    auto it = std::lower_bound(times.begin(), times.end(), relative_sec - tolerance);
    if (it != times.begin()) return *std::prev(it);
  }
  return std::nullopt;
}

// The exact end is known once the last segment has loaded. Keep it, so the range doesn't change as segments unload.
double ReplayStream::maxSeconds() const {
  const auto data = replay->getEventData();
  const auto &segments = replay->route().segments();
  if (known_end_ < 0 && data && !segments.empty()) {
    auto last = data->segments.find(segments.rbegin()->first);
    if (last != data->segments.end() && last->second->log && !last->second->log->events.empty())
      known_end_ = std::min(replay->maxSeconds(), toSeconds(last->second->log->events.back().mono_time));
  }
  return known_end_ >= 0 ? known_end_.load() : replay->maxSeconds();
}
