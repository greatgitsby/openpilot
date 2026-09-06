#pragma once
#include <future>
#include <list>
#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/replay/framereader.h"

// Independently seekable replay camera. The latest requested frame supersedes older seeks.
class AnalysisCamera {
public:
  AnalysisCamera();
  ~AnalysisCamera();
  void draw(const std::string &file, int frame, const ImVec2 &size);
  int displayedFrame() const { return displayed_frame_; }
private:
  struct Decoder;
  std::shared_ptr<Decoder> decoder_;
  std::future<RgbImage> pending_;
  GlTexture texture_;
  struct CachedFrame { std::string file; int frame; RgbImage image; };
  std::list<CachedFrame> cache_;
  size_t cache_bytes_ = 0;
  static constexpr size_t cache_limit_ = 32 * 1024 * 1024;
  std::string requested_file_, displayed_file_, error_;
  int requested_frame_ = -1, displayed_frame_ = -1;
};
