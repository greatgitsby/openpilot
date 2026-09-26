#pragma once

#include <functional>
#include <memory>
#include <set>

#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/replay/timeline.h"

ImU32 timelineColor(TimelineType type);

// One camera of one source, with a Fit/Fill overlay button and the current alert.
class VideoWidget {
public:
  explicit VideoWidget(AbstractStream *source, VisionStreamType type = VISION_STREAM_NARROW_ROAD);
  std::function<void()> togglePlayback;
  void drawVideo();
  void setVisible(bool visible);
  bool crop() const { return crop_; }
  void setCrop(bool crop) { crop_ = crop; }
  static std::set<VisionStreamType> availableStreams(AbstractStream *source);
  static const char *cameraName(VisionStreamType type);

private:
  void drawOverlays(ImDrawList *p, const ImRect &rect);

  AbstractStream *source_;
  VisionStreamType stream_type_;
  bool crop_ = false;
  std::unique_ptr<CameraWidget> camera_;
  Connections connections_;
};
