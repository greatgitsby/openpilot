#include "tools/cabana/ui/widgets/videowidget.h"

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iterator>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/pixfmt.h>
}
#include <capnp/serialize.h>

#include "tools/cabana/settings.h"
#include "tools/cabana/core/source.h"
#include "tools/cabana/streams/devicestream.h"
#include "tools/cabana/ui/threadpool.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"
#include "tools/cabana/utils/util.h"

const int MIN_VIDEO_HEIGHT = 100;
const int THUMBNAIL_MARGIN = 3;
const float POINT_10_FONT_SIZE = 13.0f;  // 10 pt at 96 dpi
const float POINT_16_FONT_SIZE = 21.0f;  // 16 pt at 96 dpi
constexpr float TOOLBAR_SEPARATOR_EXTENT = 1.0f;
const float SLIDER_HEIGHT = 15.0f;     // the handle plus a 1 px margin

// Indexed by TimelineType: None, Engaged, AlertInfo, AlertWarning, AlertCritical, UserBookmark
static const ImU32 timeline_colors[] = {
  IM_COL32(111, 143, 175, 255),
  IM_COL32(0, 163, 108, 255),
  IM_COL32(0, 255, 0, 255),
  IM_COL32(255, 195, 0, 255),
  IM_COL32(199, 0, 57, 255),
  IM_COL32(255, 0, 255, 255),
};

static Replay *getReplay() {
  auto stream = dynamic_cast<ReplayStream *>(can);
  return stream ? stream->getReplay() : nullptr;
}

// the zoomed range, or the whole route
static std::pair<double, double> displayedTimeRange() {
  return can->timeRange().value_or(std::make_pair(can->minSeconds(), can->maxSeconds()));
}

// decode with libavcodec, already linked for the replay video decoder
static bool decodeJpeg(const uint8_t *data, size_t size, RgbImage *out) {
  const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MJPEG);
  AVCodecContext *context = codec ? avcodec_alloc_context3(codec) : nullptr;
  AVFrame *frame = av_frame_alloc();
  AVPacket *packet = av_packet_alloc();
  bool ok = false;
  if (context && frame && packet && size > 0 && size <= (size_t)INT32_MAX && av_new_packet(packet, (int)size) >= 0) {
    std::copy(data, data + size, packet->data);
    ok = avcodec_open2(context, codec, nullptr) >= 0 && avcodec_send_packet(context, packet) >= 0 &&
         avcodec_receive_frame(context, frame) >= 0 && frame->width > 0 && frame->height > 0;
  }
  int chroma_x_shift = 0, chroma_y_shift = 0;
  if (ok) {
    switch ((AVPixelFormat)frame->format) {
      case AV_PIX_FMT_YUV420P: case AV_PIX_FMT_YUVJ420P: chroma_x_shift = chroma_y_shift = 1; break;
      case AV_PIX_FMT_YUV422P: case AV_PIX_FMT_YUVJ422P: chroma_x_shift = 1; break;
      case AV_PIX_FMT_YUV444P: case AV_PIX_FMT_YUVJ444P: break;
      default: ok = false; break;
    }
  }
  if (ok) {
    out->resize(frame->width, frame->height);
    const bool full_range = frame->color_range == AVCOL_RANGE_JPEG || frame->format == AV_PIX_FMT_YUVJ420P ||
                            frame->format == AV_PIX_FMT_YUVJ422P || frame->format == AV_PIX_FMT_YUVJ444P;
    const float y_scale = full_range ? 1.0f : 1.164383f;
    const float y_offset = full_range ? 0.0f : 16.0f;
    const float kr = full_range ? 1.402f : 1.596027f;
    const float kgu = full_range ? 0.344136f : 0.391762f;
    const float kgv = full_range ? 0.714136f : 0.812968f;
    const float kb = full_range ? 1.772f : 2.017232f;
    for (int y = 0; y < frame->height; ++y) {
      const uint8_t *y_row = frame->data[0] + y * frame->linesize[0];
      const uint8_t *u_row = frame->data[1] + (y >> chroma_y_shift) * frame->linesize[1];
      const uint8_t *v_row = frame->data[2] + (y >> chroma_y_shift) * frame->linesize[2];
      uint8_t *dst = out->data.data() + (size_t)y * out->bytesPerLine();
      for (int x = 0; x < frame->width; ++x) {
        const float luma = y_scale * ((float)y_row[x] - y_offset);
        const float u = (float)u_row[x >> chroma_x_shift] - 128.0f;
        const float v = (float)v_row[x >> chroma_x_shift] - 128.0f;
        const float r = luma + kr * v;
        const float g = luma - kgu * u - kgv * v;
        const float b = luma + kb * u;
        dst[x * 4 + 0] = (uint8_t)std::clamp(std::lround(r), 0L, 255L);
        dst[x * 4 + 1] = (uint8_t)std::clamp(std::lround(g), 0L, 255L);
        dst[x * 4 + 2] = (uint8_t)std::clamp(std::lround(b), 0L, 255L);
        dst[x * 4 + 3] = 255;
      }
    }
  }
  av_packet_free(&packet);
  av_frame_free(&frame);
  avcodec_free_context(&context);
  return ok;
}

VideoWidget::VideoWidget(AbstractStream *source, VisionStreamType type)
    : source_(source ? source : can), stream_type_(type) {
  auto *replay = dynamic_cast<ReplayStream *>(source_);
  auto *device = dynamic_cast<DeviceStream *>(source_);
  cam_widget_ = std::make_unique<StreamCameraView>(replay ? replay->cameraEndpoint() :
    device && device->remote() ? device->cameraServer() : "camerad", type);
  connections_.push_back(cam_widget_->clicked.connect([this]() { if (togglePlayback) togglePlayback(); else source_->pause(!source_->isPaused()); }));
  if (replay) {
    connections_.push_back(cam_widget_->connected.connect([replay]() { replay->getReplay()->requestCameraPreview(); }));
  }
  // qlog thumbnails describe the narrow road camera only.
  if (replay && type == VISION_STREAM_NARROW_ROAD) {
    connections_.push_back(replay->qLogLoaded.connect([this](std::shared_ptr<LogReader> qlog) { cam_widget_->parseQLog(qlog); }));
  }
}

const char *VideoWidget::cameraName(VisionStreamType type) {
  switch (type) {
    case VISION_STREAM_CABIN: return "Driver camera";
    case VISION_STREAM_WIDE_ROAD: return "Wide road camera";
    default: return "Road camera";
  }
}

std::set<VisionStreamType> VideoWidget::availableStreams(AbstractStream *source) {
  if (auto *device = dynamic_cast<DeviceStream *>(source); device && device->remote())
    return {VISION_STREAM_NARROW_ROAD, VISION_STREAM_CABIN, VISION_STREAM_WIDE_ROAD};
  std::set<VisionStreamType> result;
  if (auto *replay = dynamic_cast<ReplayStream *>(source)) {
    if (replay->getReplay()->hasFlag(REPLAY_FLAG_NO_VIPC)) return result;
    for (const auto camera : replay->availableCameras()) {
      result.insert(camera == CabinCam ? VISION_STREAM_CABIN : camera == WideRoadCam ? VISION_STREAM_WIDE_ROAD : VISION_STREAM_NARROW_ROAD);
    }
  }
  return result;
}

void VideoWidget::drawVideo() {
  SourceScope scope(source_);
  if (auto *device = dynamic_cast<DeviceStream *>(source_); device && device->remote()) device->setCamera(stream_type_);
  if (dynamic_cast<DummyStream *>(source_)) {
    // An unresolved saved route must never subscribe to the live camerad endpoint.
    cam_widget_->setVisible(false);
    ImGui::BeginChild("unloaded_video", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    const char *title = "Source not loaded";
    const char *hint = "Open saved routes or choose a route for this source.";
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + std::max(0.f, (avail.y - ImGui::GetTextLineHeightWithSpacing() * 2) / 2));
    for (const char *text : {title, hint}) {
      ImGui::SetCursorPosX(ImGui::GetStyle().WindowPadding.x + std::max(0.f, (avail.x - ImGui::CalcTextSize(text).x) / 2));
      ImGui::TextDisabled("%s", text);
    }
    ImGui::EndChild();
    return;
  }
  const ImVec2 origin = ImGui::GetCursorScreenPos();
  const ImVec2 avail = ImGui::GetContentRegionAvail();
  // Submit the overlay first so it owns clicks, then composite it above the video.
  ImDrawList *draw = ImGui::GetWindowDrawList();
  ImDrawListSplitter layers;
  layers.Split(draw, 2);
  layers.SetCurrentChannel(draw, 1);
  ImGui::SetCursorScreenPos(ImVec2(origin.x + std::max(0.f, avail.x - iconButtonWidth() - 8), origin.y + 8));
  if (overlayIconButton("crop_video", crop_ ? icon::ASPECT_RATIO_FILL : icon::ASPECT_RATIO,
                        crop_ ? "Fill: crop edges to fill this tab. Click to fit." : "Fit: show the entire frame. Click to fill.")) crop_ = !crop_;
  layers.SetCurrentChannel(draw, 0);
  ImGui::SetCursorScreenPos(origin);
  cam_widget_->setCrop(crop_);
  cam_widget_->draw(ImVec2(std::max(1.0f, avail.x), std::max(1.0f, avail.y)));
  layers.Merge(draw);
}

void VideoWidget::setVisible(bool visible) {
  cam_widget_->setVisible(visible && !dynamic_cast<DummyStream *>(source_));
}

void Slider::draw(double thumbnail_time) {
  ImGui::InvisibleButton("##slider", ImVec2(std::max(1.0f, ImGui::GetContentRegionAvail().x), SLIDER_HEIGHT));
  rect_ = ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
  const bool hovered = ImGui::IsItemHovered();
  left_ = hovered_ && !hovered;
  hovered_ = hovered;

  if (ImGui::IsItemActivated()) handleMousePress();
  if (slider_down_) {
    if (ImGui::IsItemActive()) {
      // the handle keeps its grab offset while dragging
      setValue(pixelPosToRangeValue(ImGui::GetMousePos().x - click_offset_));
    } else {
      slider_down_ = false;
      sliderReleased();
    }
  }
  paint(thumbnail_time);
}

void Slider::drawFilmstrip(float track_width, float height,
                           const std::function<void(ImDrawList *, ImVec2, ImVec2)> &background, bool selected) {
  ImGui::InvisibleButton("##slider", ImVec2(std::max(1.0f, track_width), std::max(1.0f, height)));
  rect_ = ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
  const bool hovered = ImGui::IsItemHovered();
  left_ = hovered_ && !hovered;
  hovered_ = hovered;
  if (ImGui::IsItemActivated()) slider_down_ = true;
  if (slider_down_) {
    if (ImGui::IsItemActive()) {
      const float fraction = std::clamp((ImGui::GetMousePos().x - rect_.Min.x) / width(), 0.0f, 1.0f);
      setValue(minimum() + (int)std::lround(fraction * (maximum() - minimum())));
    } else {
      slider_down_ = false;
      sliderReleased();
    }
  }

  ImDrawList *p = ImGui::GetWindowDrawList();
  p->PushClipRect(rect_.Min, rect_.Max, true);
  p->AddRectFilled(rect_.Min, rect_.Max, ImGui::GetColorU32(ImGuiCol_FrameBg));
  if (background) background(p, rect_.Min, rect_.Max);
  const ImRect ribbon(ImVec2(rect_.Min.x, std::max(rect_.Min.y, rect_.Max.y - 8.0f)), rect_.Max);
  paintTimeline(p, ribbon);
  const float fraction = (float)(value() - minimum()) / std::max(1, maximum() - minimum());
  const float x = std::clamp(rect_.Min.x + fraction * width(), rect_.Min.x + 1.0f, rect_.Max.x);
  p->AddLine(ImVec2(x + 1, rect_.Min.y), ImVec2(x + 1, rect_.Max.y), IM_COL32(0, 0, 0, 160), 3.0f);
  p->AddLine(ImVec2(x, rect_.Min.y), ImVec2(x, rect_.Max.y), IM_COL32(255, 255, 255, 245), 2.0f);
  p->AddTriangleFilled(ImVec2(x - 5, rect_.Min.y), ImVec2(x + 5, rect_.Min.y),
                       ImVec2(x, rect_.Min.y + 6), IM_COL32(255, 255, 255, 245));
  p->PopClipRect();
  p->AddRect(rect_.Min, rect_.Max, ImGui::GetColorU32(selected ? ImGuiCol_SliderGrabActive : ImGuiCol_Border),
             2.0f, 0, selected ? 2.0f : 1.0f);
}

ImRect Slider::handleRect() const {
  const float handle_width = SLIDER_LENGTH;
  const float handle_height = std::min(SLIDER_THICKNESS, rect_.GetHeight());
  const int range = std::max(1, maximum() - minimum());
  const float x = rect_.Min.x + (float)(value() - minimum()) / range * std::max(0.0f, width() - handle_width);
  const float y = rect_.GetCenter().y - handle_height / 2;
  return ImRect(ImVec2(x, y), ImVec2(x + handle_width, y + handle_height));
}

// handle left edge (window x) -> value over the groove minus the handle width
int Slider::pixelPosToRangeValue(float x) const {
  const float handle_width = SLIDER_LENGTH;
  const float span = std::max(1.0f, width() - handle_width);
  return minimum() + (int)std::lround((maximum() - minimum()) * std::clamp((x - rect_.Min.x) / span, 0.0f, 1.0f));
}

void Slider::paint(double thumbnail_time) {
  ImDrawList *p = ImGui::GetWindowDrawList();

  ImRect handle_rect = handleRect();
  ImRect groove_rect = rect_;

  // adjust the groove height to match the handle height, rounded up to whole pixels
  float handle_height = handle_rect.GetHeight();
  const float groove_height = std::ceil(handle_height * 0.5f);
  const float center_y = rect_.GetCenter().y;
  groove_rect.Min.y = std::floor(center_y - groove_height / 2);
  groove_rect.Max.y = groove_rect.Min.y + groove_height;

  paintTimeline(p, groove_rect);
  drawSliderHandle(p, handle_rect);

  if (thumbnail_time >= 0) {
    const double min = minimum() / factor;
    const double span = std::max((maximum() - minimum()) / factor, 1e-9);
    float left = rect_.Min.x + (float)((thumbnail_time - min) * width() / span) - 1;
    ImRect rc(ImVec2(left, rect_.Min.y + 1), ImVec2(left + 2, rect_.Max.y - 1));
    p->AddRectFilled(rc.Min, rc.Max, ImGui::GetColorU32(ImGuiCol_Header), 1.0f);
  }
}

void Slider::paintTimeline(ImDrawList *p, const ImRect &groove_rect) {
  p->AddRectFilled(groove_rect.Min, groove_rect.Max, toImU32(graphicColor(fromImVec4(ImGui::ColorConvertU32ToFloat4(timeline_colors[(int)TimelineType::None])), palette().window)), groove_rect.GetHeight() * 0.5f);

  double min = minimum() / factor;
  double max = maximum() / factor;
  const double span = std::max(max - min, 1e-9);

  auto fillRange = [&](double begin, double end, ImU32 color) {
    if (begin > max || end < min) return;

    // the edges truncate to whole pixels and the right edge is inclusive, so even an event shorter than a
    // pixel paints one full pixel in its color instead of an anti-aliased smear
    ImRect r = groove_rect;
    r.Min.x = rect_.Min.x + std::floor(((std::max(min, begin) - min) / span) * width());
    r.Max.x = rect_.Min.x + std::floor(((std::min(max, end) - min) / span) * width()) + 1.0f;
    p->AddRectFilled(r.Min, r.Max, color);
  };

  if (auto replay = getReplay()) {
    for (const auto &entry : *replay->getTimeline()) {
      fillRange(entry.start_time, entry.end_time, toImU32(graphicColor(fromImVec4(ImGui::ColorConvertU32ToFloat4(timeline_colors[(int)entry.type])), palette().window)));
    }

    ImU32 empty_color = ImGui::GetColorU32(ImGuiCol_WindowBg, 160 / 255.0f);
    const auto event_data = replay->getEventData();
    for (const auto &[n, _] : replay->route().segments()) {
      if (!event_data->isSegmentLoaded(n))
        fillRange(n * 60.0, (n + 1) * 60.0, empty_color);
    }
  }
}

void Slider::handleMousePress() {
  // a press on the handle starts a drag and remembers the grab offset
  const ImRect handle_rect = handleRect();
  if (handle_rect.Contains(ImGui::GetMousePos())) {
    slider_down_ = true;
    click_offset_ = ImGui::GetMousePos().x - handle_rect.Min.x;
    return;
  }
  slider_down_ = true;
  click_offset_ = SLIDER_LENGTH * 0.5f;
  setValue(pixelPosToRangeValue(ImGui::GetMousePos().x - click_offset_));
}

StreamCameraView::StreamCameraView(std::string stream_name, VisionStreamType stream_type)
    : CameraWidget(stream_name, stream_type) {
  big_thumbnail_texture_.mipmap = true;  // the hover thumbnail is drawn at a quarter of the stored size
}

StreamCameraView::~StreamCameraView() {
  for (auto &pending : pending_thumbnails_) pending.done.wait();
}

void StreamCameraView::parseQLog(std::shared_ptr<LogReader> qlog) {
  auto thumbnails = std::make_shared<std::map<uint64_t, RgbImage>>();
  auto done = ThreadPool::instance().run([qlog, thumbnails]() {
    for (const Event &e : qlog->events) {
      if (e.which != cereal::Event::Which::THUMBNAIL) continue;
      capnp::FlatArrayMessageReader reader(e.data);
      auto thumb_data = reader.getRoot<cereal::Event>().getThumbnail();
      auto image_data = thumb_data.getThumbnail();
      if (RgbImage thumb; decodeJpeg(image_data.begin(), image_data.size(), &thumb)) {
        (*thumbnails)[thumb_data.getTimestampEof()] = std::move(thumb);
      }
    }
  });
  pending_thumbnails_.push_back({std::move(done), std::move(thumbnails)});
}

void StreamCameraView::collectThumbnails() {
  for (auto it = pending_thumbnails_.begin(); it != pending_thumbnails_.end();) {
    if (it->done.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
      ++it;
      continue;
    }
    for (auto &[ts, thumb] : *it->thumbnails) big_thumbnails_[ts] = std::move(thumb);
    it = pending_thumbnails_.erase(it);
  }
}

void StreamCameraView::draw(const ImVec2 &size) {
  collectThumbnails();
  CameraWidget::draw(size);

  ImDrawList *p = ImGui::GetWindowDrawList();
  if (auto *replay = getReplay()) {
    if (auto alert = replay->findAlertAtTime(can->currentSec()))
      drawAlert(p, rect(), *alert, ImGui::GetFontSize(), ImGui::GetStyle().ChildRounding);
  }

  if (can->isPaused()) {
    ImFont *font = boldFont();
    const char *text = "PAUSED";
    const ImVec2 text_size = font->CalcTextSizeA(POINT_16_FONT_SIZE, FLT_MAX, 0.0f, text);
    const ImVec2 center = rect().GetCenter();
    const ImVec2 pos(center.x - text_size.x / 2, center.y - text_size.y / 2);
    p->AddRectFilled(ImVec2(pos.x - 4, pos.y - 2), ImVec2(pos.x + text_size.x + 4, pos.y + text_size.y + 2), ImGui::GetColorU32(palette().badge), ImGui::GetStyle().FrameRounding);
    p->AddText(font, POINT_16_FONT_SIZE, pos, ImGui::GetColorU32(palette().text_selected), text);
  }
}

const RgbImage *StreamCameraView::thumbnailAt(double sec) {
  auto it = big_thumbnails_.lower_bound(can->toMonoTime(sec));
  if (it == big_thumbnails_.end()) return nullptr;
  if (big_thumbnail_texture_.id == 0 || big_thumbnail_texture_.key != it->first) {
    big_thumbnail_texture_.upload(it->second);
    big_thumbnail_texture_.key = it->first;
  }
  return &it->second;
}

void StreamCameraView::drawThumbnail(ImDrawList *p, double sec, const ImRect &timeline) {
  collectThumbnails();
  if (const RgbImage *image = thumbnailAt(sec)) {
    const float h = MIN_VIDEO_HEIGHT - THUMBNAIL_MARGIN * 2;
    const float w = std::max(1.0f, h * image->width / image->height);
    auto [min_sec, max_sec] = displayedTimeRange();
    const float pos = timeline.Min.x + (sec - min_sec) * timeline.GetWidth() / std::max(0.001, max_sec - min_sec);
    const ImGuiViewport *viewport = ImGui::GetWindowViewport();
    const float left = viewport->WorkPos.x + THUMBNAIL_MARGIN;
    const float right = viewport->WorkPos.x + viewport->WorkSize.x - w - THUMBNAIL_MARGIN;
    const float x = std::clamp(pos - w / 2, left, std::max(left, right));
    const float y = std::max(viewport->WorkPos.y + THUMBNAIL_MARGIN,
                             timeline.Min.y - h - ImGui::GetTextLineHeightWithSpacing());
    ImRect thumb_rect(ImVec2(x, y), ImVec2(x + w, y + h));
    p->AddImageRounded(big_thumbnail_texture_.ref(), thumb_rect.Min, thumb_rect.Max, ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, ImGui::GetStyle().FrameRounding);
    p->AddRect(thumb_rect.Min, thumb_rect.Max, IM_COL32_WHITE, ImGui::GetStyle().FrameRounding, 0, 2.0f);
    // look up the alert at the hovered time, the thumbnail frame itself can be seconds away
    if (auto alert = getReplay()->findAlertAtTime(sec)) {
      drawAlert(p, thumb_rect, *alert, POINT_10_FONT_SIZE, ImGui::GetStyle().FrameRounding);
    }
    drawTime(p, thumb_rect, sec);
  }
}

void StreamCameraView::drawTime(ImDrawList *p, const ImRect &rect, double seconds) {
  char text[32];
  snprintf(text, sizeof(text), "%.2f", seconds);
  ImFont *font = ImGui::GetFont();
  const ImVec2 text_size = font->CalcTextSizeA(POINT_10_FONT_SIZE, FLT_MAX, 0.0f, text);
  // centered horizontally, above the bottom margin
  const ImVec2 pos(rect.GetCenter().x - text_size.x / 2, rect.Max.y - THUMBNAIL_MARGIN - text_size.y);
  p->AddRectFilled(ImVec2(pos.x - 4, pos.y - 2), ImVec2(pos.x + text_size.x + 4, pos.y + text_size.y + 2), ImGui::GetColorU32(palette().badge), ImGui::GetStyle().FrameRounding);
  p->AddText(font, POINT_10_FONT_SIZE, pos, ImGui::GetColorU32(palette().text_selected), text);
}

void StreamCameraView::drawAlert(ImDrawList *p, const ImRect &rect, const Timeline::Entry &alert, float font_size, float rounding) {
  const ImU32 pen = IM_COL32_WHITE;
  // Opaque backing keeps alert text readable over every camera frame.
  const auto source = fromImVec4(ImGui::ColorConvertU32ToFloat4(timeline_colors[int(alert.type)]));
  const ImU32 color = toImU32(contrastColor(source, fromImVec4(palette().text_selected)));
  std::string text = alert.text1;
  if (!alert.text2.empty()) text += "\n" + alert.text2;

  const ImRect &text_rect = rect;
  ImFont *font = ImGui::GetFont();
  const float wrap_width = std::max(1.0f, text_rect.GetWidth());
  const ImVec2 r = font->CalcTextSizeA(font_size, FLT_MAX, wrap_width, text.c_str());
  p->AddRectFilled(ImVec2(text_rect.Min.x, text_rect.Min.y), ImVec2(text_rect.Max.x, text_rect.Min.y + r.y), color, rounding, ImDrawFlags_RoundCornersTop);
  // each line is centered, wrapped continuations stay left aligned
  float y = text_rect.Min.y;
  for (const auto &line : utils::split(text, '\n')) {
    const ImVec2 line_size = font->CalcTextSizeA(font_size, FLT_MAX, wrap_width, line.c_str());
    p->AddText(font, font_size, ImVec2(text_rect.Min.x + (text_rect.GetWidth() - line_size.x) / 2, y), pen, line.c_str(), nullptr, wrap_width);
    y += line_size.y;
  }
}
