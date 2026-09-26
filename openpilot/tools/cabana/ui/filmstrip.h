#pragma once

#include <array>
#include <future>
#include <memory>
#include <string>

#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/cabana/streams/replaystream.h"

// Twelve route thumbnails, decoded on a worker from frames the replay has cached. A tile keeps its thumbnail
// once filled, so segments leaving the cache don't blank it. Textures stay on the UI thread.
class RouteFilmstrip {
public:
  void update(ReplayStream *source);
  void draw(ImDrawList *draw, ImVec2 min, ImVec2 max);

private:
  static constexpr int COUNT = 12;
  using Images = std::array<RgbImage, COUNT>;
  std::array<GlTexture, COUNT> textures_;
  std::future<void> pending_;
  std::shared_ptr<Images> result_;
  std::string key_;
  double next_check_ = 0;
};
