#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "json11/json11.hpp"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/ui/filmstrip.h"
#include "tools/cabana/ui/widgets/videowidget.h"

// Persistent transport shared by every tab; route time + timeline_offset = workspace time.
class PlaybackTimeline {
public:
  void setSources(const std::vector<AbstractStream *> &sources);
  void selectSource(const std::string &id, VisionStreamType camera = VISION_STREAM_NARROW_ROAD);
  const std::string &selectedSource() const { return selected_id_; }
  uint64_t selectionRevision() const { return selection_revision_; }
  float height(size_t max_tracks = 3) const;
  void draw(bool expanded = true);
  void tick();
  void handleShortcuts();
  json11::Json snapshot() const;
  void restore(const json11::Json &state);
  void renameSource(const std::string &from, const std::string &to);

  void seek(double route_seconds);
  void togglePlayback();
  void setPaused(bool paused);
  void stepFrame(bool forward);
  void alignCurrentPositions();

private:
  AbstractStream *source(const std::string &id) const;
  AbstractStream *selected() const { return source(selected_id_); }
  std::vector<AbstractStream *> controlled(AbstractStream *master) const;
  std::pair<double, double> groupRange(AbstractStream *master) const;
  void seekGroup(AbstractStream *master, double route_seconds);
  bool loopApplies(AbstractStream *master) const;
  void drawSettings();
  void drawTrack(AbstractStream *source);
  void restoreSource(AbstractStream *source);

  std::vector<AbstractStream *> sources_;
  std::vector<std::string> slots_;  // unloaded sources, whose saved alignment waits in saved_
  json11::Json saved_;
  std::string selected_id_;
  uint64_t selection_revision_ = 0;
  VisionStreamType selected_camera_ = VISION_STREAM_NARROW_ROAD;
  std::set<std::string> linked_;
  std::string linked_master_id_;
  std::string loop_source_id_;
  std::map<std::string, std::unique_ptr<RouteFilmstrip>> filmstrips_;
  std::map<std::string, std::string> offset_inputs_;
  bool loop_ = false;
  double loop_start_ = 0;
  double loop_end_ = 10;
  std::string loop_start_input_ = "0";
  std::string loop_end_input_ = "10";
  double last_sync_ = 0;
  bool scrub_resume_ = false;
  double scrub_preview_time_ = 0;
  std::string status_;
};
