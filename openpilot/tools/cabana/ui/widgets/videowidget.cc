#include "tools/cabana/ui/widgets/videowidget.h"

#include <algorithm>
#include <cfloat>

#include "tools/cabana/core/source.h"
#include "tools/cabana/settings.h"
#include "tools/cabana/streams/devicestream.h"
#include "tools/cabana/streams/replaystream.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"

const float POINT_16_FONT_SIZE = 21.0f;  // 16 pt at 96 dpi

ImU32 timelineColor(TimelineType type) {
  static const ImU32 colors[] = {
    IM_COL32(111, 143, 175, 255), IM_COL32(0, 163, 108, 255), IM_COL32(0, 255, 0, 255),
    IM_COL32(255, 195, 0, 255), IM_COL32(199, 0, 57, 255), IM_COL32(255, 0, 255, 255),
  };
  return colors[(int)type];
}

VideoWidget::VideoWidget(AbstractStream *source, VisionStreamType type) : source_(source), stream_type_(type) {
  auto *replay = dynamic_cast<ReplayStream *>(source_);
  auto *device = dynamic_cast<DeviceStream *>(source_);
  camera_ = std::make_unique<CameraWidget>(replay ? replay->cameraEndpoint() :
    device && device->remote() ? device->cameraServer() : "camerad", type);
  connections_.push_back(camera_->clicked.connect([this]() { if (togglePlayback) togglePlayback(); else source_->pause(!source_->isPaused()); }));
  if (replay) {
    connections_.push_back(camera_->connected.connect([replay]() { replay->getReplay()->requestCameraPreview(); }));
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
    camera_->setVisible(false);
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + std::max(0.f, (avail.y - ImGui::GetTextLineHeightWithSpacing() * 2) / 2));
    for (const char *text : {"Source not loaded", "Open saved routes or choose a route for this source."}) {
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(0.f, (avail.x - ImGui::CalcTextSize(text).x) / 2));
      ImGui::TextDisabled("%s", text);
    }
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
                        crop_ ? "Fill: crop edges to fill this tab. Click to fit." : "Fit: show the entire frame. Click to fill.")) settings.crop_video = crop_ = !crop_;
  layers.SetCurrentChannel(draw, 0);
  ImGui::SetCursorScreenPos(origin);
  camera_->setCrop(crop_);
  camera_->draw(ImVec2(std::max(1.0f, avail.x), std::max(1.0f, avail.y)));
  drawOverlays(draw, camera_->rect());
  layers.Merge(draw);
}

void VideoWidget::drawOverlays(ImDrawList *p, const ImRect &rect) {
  auto *replay = dynamic_cast<ReplayStream *>(source_);
  if (auto alert = replay ? replay->getReplay()->findAlertAtTime(source_->currentSec()) : std::nullopt) {
    // Opaque backing keeps alert text readable over every camera frame; each line is centered.
    const auto lines = utils::split(alert->text2.empty() ? alert->text1 : alert->text1 + "\n" + alert->text2, '\n');
    const float wrap = std::max(1.0f, rect.GetWidth());
    float height = 0;
    for (const auto &line : lines) height += ImGui::CalcTextSize(line.c_str(), nullptr, false, wrap).y;
    const auto color = contrastColor(fromImVec4(ImGui::ColorConvertU32ToFloat4(timelineColor(alert->type))), fromImVec4(palette().text_selected));
    p->AddRectFilled(rect.Min, ImVec2(rect.Max.x, rect.Min.y + height), toImU32(color), ImGui::GetStyle().ChildRounding, ImDrawFlags_RoundCornersTop);
    float y = rect.Min.y;
    for (const auto &line : lines) {
      const ImVec2 size = ImGui::CalcTextSize(line.c_str(), nullptr, false, wrap);
      p->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(rect.Min.x + (rect.GetWidth() - size.x) / 2, y), IM_COL32_WHITE, line.c_str(), nullptr, wrap);
      y += size.y;
    }
  }
  if (source_->isPaused()) {
    ImFont *font = boldFont();
    const ImVec2 text_size = font->CalcTextSizeA(POINT_16_FONT_SIZE, FLT_MAX, 0.0f, "PAUSED");
    const ImVec2 pos(rect.GetCenter().x - text_size.x / 2, rect.GetCenter().y - text_size.y / 2);
    p->AddRectFilled(ImVec2(pos.x - 4, pos.y - 2), ImVec2(pos.x + text_size.x + 4, pos.y + text_size.y + 2), ImGui::GetColorU32(palette().badge), ImGui::GetStyle().FrameRounding);
    p->AddText(font, POINT_16_FONT_SIZE, pos, ImGui::GetColorU32(palette().text_selected), "PAUSED");
  }
}

void VideoWidget::setVisible(bool visible) {
  camera_->setVisible(visible && !dynamic_cast<DummyStream *>(source_));
}
