#pragma once

#include <array>
#include <future>
#include <memory>
#include <string>

#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/cabana/streams/replaystream.h"

// Independent, bounded thumbnail cache. Video decoders stay on the worker; textures stay on the UI thread.
class RouteFilmstrip {
public:
  void update(ReplayStream *source);
  void draw(ImDrawList *draw, ImVec2 min, ImVec2 max);

private:
  static constexpr int COUNT = 12;
  struct Result {
    std::array<RgbImage, COUNT> images;
    std::array<std::string, COUNT> keys;
  };
  std::array<GlTexture, COUNT> textures_;
  std::future<void> pending_;
  std::shared_ptr<Result> result_;
  std::array<std::string, COUNT> tile_keys_;
  std::string pending_key_;
  std::string key_;
  double next_check_ = 0;
};
