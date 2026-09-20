#include "tools/cabana/ui/filmstrip.h"

#include <capnp/dynamic.h>

#include "common/yuv.h"
#include "tools/cabana/ui/threadpool.h"

void RouteFilmstrip::update(ReplayStream *source) {
  if (!source) return;
  const auto cameras = source->availableCameras();
  if (cameras.empty()) return;
  const CameraType camera = cameras.count(NarrowRoadCam) ? NarrowRoadCam : *cameras.begin();
  const double begin = source->minSeconds(), end = source->maxSeconds();
  const std::string key = source->cameraEndpoint() + ":" + std::to_string(camera) + ":" +
                          std::to_string(begin) + ":" + std::to_string(end);
  if (key != key_) {
    key_ = key;
    tile_keys_.fill({});
    for (auto &texture : textures_) texture.destroy();
    next_check_ = 0;
  }
  if (pending_.valid()) {
    if (pending_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
    try {
      pending_.get();
      if (pending_key_ == key_) {
        for (int i = 0; i < COUNT; ++i) {
          if (result_->images[i].isNull()) continue;
          textures_[i].upload(result_->images[i]);
          tile_keys_[i] = std::move(result_->keys[i]);
        }
      }
    } catch (...) { /* Keep existing tiles when a video cannot be decoded. */ }
    result_.reset();
  }
  if (ImGui::GetTime() < next_check_) return;
  next_check_ = ImGui::GetTime() + 1;
  auto data = source->getReplay()->getEventData();
  const auto which = camera == NarrowRoadCam ? cereal::Event::NARROW_ROAD_ENCODE_IDX :
                     camera == CabinCam ? cereal::Event::CABIN_ENCODE_IDX : cereal::Event::WIDE_ROAD_ENCODE_IDX;
  result_ = std::make_shared<Result>();
  pending_key_ = key_;
  const auto start = source->beginMonoTime();
  pending_ = ThreadPool::instance().run([data, result = result_, cached = tile_keys_, key, camera, which, begin, end, start]() {
    // Sample in time order and retain only one independent decoder at a time.
    // The event snapshot owns every segment accessed here, including after route closure.
    std::unique_ptr<FrameReader> reader;
    int reader_segment = -1;
    for (int tile = 0; tile < COUNT; ++tile) {
      const uint64_t target = start + (begin + (end - begin) * (tile + .5) / COUNT) * 1e9;
      auto it = std::upper_bound(data->events.begin(), data->events.end(), target,
                                [](uint64_t time, const Event &event) { return time < event.mono_time; });
      const Event *frame = nullptr;
      while (it != data->events.begin()) {
        --it;
        if (target - it->mono_time > 2e9) break;
        if (it->which == which && it->eidx_segnum >= 0) { frame = &*it; break; }
      }
      // Preserve an existing thumbnail after its segment leaves the replay cache.
      if (!frame) continue;
      auto segment = data->segments.find(frame->eidx_segnum);
      if (segment == data->segments.end()) continue;
      auto *original = segment->second->frames[camera].get();
      if (!original || !original->input_ctx) continue;
      capnp::FlatArrayMessageReader message(frame->data);
      auto event = message.getRoot<cereal::Event>();
      auto index = capnp::AnyStruct::Reader(event).getPointerSection()[0].getAs<cereal::EncodeIndex>();
      const std::string tile_key = key + ":" + std::to_string(frame->eidx_segnum) + ":" + std::to_string(index.getSegmentId());
      if (cached[tile] == tile_key) continue;
      if (reader_segment != frame->eidx_segnum) {
        reader.reset();
        reader_segment = frame->eidx_segnum;
        reader = std::make_unique<FrameReader>();
        if (!reader->loadFromFile(camera, original->input_ctx->url, true)) reader.reset();
      }
      if (!reader) continue;
      std::vector<uint8_t> pixels(size_t(reader->width) * reader->height * 3 / 2);
      VisionBuf buffer;
      buffer.addr = pixels.data();
      buffer.init_yuv(reader->width, reader->height, reader->width, reader->width * reader->height);
      if (!reader->get(index.getSegmentId(), &buffer)) continue;
      RgbImage full;
      full.resize(reader->width, reader->height);
      yuv::nv12_to_rgba(buffer.y, buffer.stride, buffer.uv, buffer.stride,
                       full.data.data(), full.bytesPerLine(), full.width, full.height);
      auto &thumb = result->images[tile];
      result->keys[tile] = tile_key;
      thumb.resize(160, std::max(1, full.height * 160 / full.width));
      for (int y = 0; y < thumb.height; ++y) {
        for (int x = 0; x < thumb.width; ++x) {
          const auto *pixel = &full.data[(size_t(y * full.height / thumb.height) * full.width + x * full.width / thumb.width) * 4];
          std::copy_n(pixel, 4, &thumb.data[(size_t(y) * thumb.width + x) * 4]);
        }
      }
    }
  });
}

void RouteFilmstrip::draw(ImDrawList *draw, ImVec2 min, ImVec2 max) {
  const float width = (max.x - min.x) / COUNT;
  for (int i = 0; i < COUNT; ++i) {
    const ImRect tile(ImVec2(min.x + i * width, min.y), ImVec2(min.x + (i + 1) * width, max.y));
    if (textures_[i].id) {
      const auto placement = videoPlacement(tile, float(textures_[i].width) / textures_[i].height, true);
      draw->AddImage(textures_[i].ref(), placement.min, placement.max, placement.uv0, placement.uv1);
    }
    if (i) draw->AddLine(tile.Min, ImVec2(tile.Min.x, tile.Max.y), IM_COL32(0, 0, 0, 70));
  }
}
