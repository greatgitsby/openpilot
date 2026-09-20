#pragma once

#include <algorithm>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"

#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/cabana/ui/widgets/tabbar.h"
#include "tools/cabana/ui/tools/routeinfo.h"
#include "tools/replay/logreader.h"
#include "tools/cabana/streams/replaystream.h"
#include "tools/cabana/ui/icons.h"

class Slider {
public:
  Slider() = default;
  double currentSecond() const { return value() / factor; }
  void setCurrentSecond(double sec) { setValue(sec * factor); }
  void setTimeRange(double min, double max) { setRange(min * factor, max * factor); }
  int value() const { return value_; }
  void setValue(int v) { value_ = std::clamp(v, minimum_, maximum_); }
  void setRange(int min, int max) { minimum_ = min; maximum_ = std::max(min, max); setValue(value_); }
  int minimum() const { return minimum_; }
  int maximum() const { return maximum_; }
  bool isSliderDown() const { return slider_down_; }
  float width() const { return rect_.GetWidth(); }
  const ImRect &rect() const { return rect_; }
  bool underMouse() const { return hovered_; }
  bool mouseLeft() const { return left_; }  // the mouse left the slider in the last draw()
  void draw(double thumbnail_time);  // thumbnail_time < 0: no thumbnail marker
  void drawFilmstrip(float width, float height,
                     const std::function<void(ImDrawList *, ImVec2, ImVec2)> &background, bool selected = false);
  static constexpr double factor = 1000.0;

  Observable<> sliderReleased;

private:
  void handleMousePress();
  void paint(double thumbnail_time);
  void paintTimeline(ImDrawList *p, const ImRect &groove_rect);
  ImRect handleRect() const;
  int pixelPosToRangeValue(float x) const;
  int minimum_ = 0;
  int maximum_ = 99;
  int value_ = 0;
  bool slider_down_ = false;
  float click_offset_ = 0;  // where inside the handle the drag started
  bool hovered_ = false;
  bool left_ = false;
  ImRect rect_;
};

class StreamCameraView : public CameraWidget {
public:
  StreamCameraView(std::string stream_name, VisionStreamType stream_type);
  ~StreamCameraView();
  void draw(const ImVec2 &size);
  void drawThumbnail(ImDrawList *p, double sec, const ImRect &timeline);
  void parseQLog(std::shared_ptr<LogReader> qlog);  // decodes the thumbnails on the thread pool

private:
  struct PendingThumbnails {
    std::future<void> done;
    std::shared_ptr<std::map<uint64_t, RgbImage>> thumbnails;
  };
  void collectThumbnails();  // moves the decoded thumbnails in once a parseQLog task is done
  // the first thumbnail at or after sec, uploaded to big_thumbnail_texture_; nullptr when there is none
  const RgbImage *thumbnailAt(double sec);
  void drawAlert(ImDrawList *p, const ImRect &rect, const Timeline::Entry &alert, float font_size, float rounding);
  void drawTime(ImDrawList *p, const ImRect &rect, double seconds);

  std::map<uint64_t, RgbImage> big_thumbnails_;
  GlTexture big_thumbnail_texture_;  // the currently shown thumbnail
  std::vector<PendingThumbnails> pending_thumbnails_;
};

class VideoWidget {
public:
  explicit VideoWidget(AbstractStream *source = nullptr, VisionStreamType type = VISION_STREAM_NARROW_ROAD);
  std::function<void()> togglePlayback;
  void drawVideo();
  void setVisible(bool visible);
  bool crop() const { return crop_; }
  void setCrop(bool crop) { crop_ = crop; }
  VisionStreamType streamType() const { return stream_type_; }
  static std::set<VisionStreamType> availableStreams(AbstractStream *source);
  static const char *cameraName(VisionStreamType type);

private:
  AbstractStream *source_;
  VisionStreamType stream_type_;
  bool crop_ = false;
  std::unique_ptr<StreamCameraView> cam_widget_;
  Connections connections_;
};
