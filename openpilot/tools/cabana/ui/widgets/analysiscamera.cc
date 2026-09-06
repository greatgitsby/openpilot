#include "tools/cabana/ui/widgets/analysiscamera.h"
#include "common/yuv.h"
#include "tools/cabana/settings.h"

struct AnalysisCamera::Decoder {
  std::unique_ptr<FrameReader> reader;
  std::string file;
  std::atomic<bool> abort = false;
  std::vector<uint8_t> bytes;
  struct Request {
    std::string file;
    int frame = -1;
    bool operator==(const Request &other) const { return file == other.file && frame == other.frame; }
  };
  struct Result { Request request; RgbImage image; std::string error; };
  std::mutex mutex;
  std::condition_variable wake;
  Request wanted, completed;
  std::optional<Result> ready;

  void run() {
    for (;;) {
      Request request;
      {
        std::unique_lock lock(mutex);
        wake.wait(lock, [&] { return abort || !(wanted == completed); });
        if (abort) return;
        request = wanted;
      }
      Result result{request, {}, {}};
      try { if (!request.file.empty() && request.frame >= 0) result.image = get(request.file, request.frame); }
      catch (const std::exception &e) { result.error = e.what(); }
      {
        std::lock_guard lock(mutex);
        completed = request;
        ready = std::move(result);
      }
    }
  }
  RgbImage get(const std::string &path, int frame) {
    if (file != path) {
      reader = std::make_unique<FrameReader>(true);
      if (!reader->load(NarrowRoadCam, path, true, &abort, true)) { file.clear(); throw std::runtime_error("Unable to load camera file"); }
      file = path;
    }
    if (abort) return {};
    if (reader->width <= 0 || reader->height <= 0 || reader->width > 8192 || reader->height > 8192) throw std::runtime_error("Invalid camera dimensions");
    int width = reader->width, height = reader->height;
    bytes.resize(size_t(width) * height * 3 / 2);
    VisionBuf buffer;
    buffer.width = width; buffer.height = height; buffer.stride = width;
    buffer.y = bytes.data(); buffer.uv = bytes.data() + size_t(width) * height;
    if (!reader->get(frame, &buffer)) throw std::runtime_error("Camera frame unavailable");
    RgbImage result; result.resize(width, height);
    yuv::nv12_to_rgba(buffer.y, width, buffer.uv, width, result.data.data(), result.bytesPerLine(), width, height);
    return result;
  }
};
AnalysisCamera::AnalysisCamera() : decoder_(std::make_shared<Decoder>()) {
  // The worker owns its state until it exits. Hiding a pane never waits on file I/O or decoding,
  // and no worker touches the pane or its GL texture after destruction.
  std::thread([decoder = decoder_] { decoder->run(); }).detach();
}
AnalysisCamera::~AnalysisCamera() {
  { std::lock_guard lock(decoder_->mutex); decoder_->abort = true; }
  decoder_->wake.notify_one();
}
void AnalysisCamera::draw(const std::string &file, int frame, const ImVec2 &size) {
  std::optional<Decoder::Result> ready;
  {
    std::lock_guard lock(decoder_->mutex);
    ready.swap(decoder_->ready);
  }
  if (ready) {
    auto &[request, image, error] = *ready;
    if (request.file == file) error_ = error;
    if (!image.isNull()) {
      // A completed pre-seek request must not overwrite a closer cached frame.
      if (request.file == file && (displayed_file_ != file ||
          std::abs(request.frame - frame) <= std::abs(displayed_frame_ - frame))) {
        texture_.upload(image); displayed_file_ = request.file; displayed_frame_ = request.frame;
      }
      cache_bytes_ += image.data.size();
      cache_.push_front({request.file, request.frame, std::move(image)});
      while (cache_bytes_ > cache_limit_ && cache_.size() > 1) { cache_bytes_ -= cache_.back().image.data.size(); cache_.pop_back(); }
    }
  }
  if (displayed_file_ != file || displayed_frame_ != frame) {
    auto cached = std::find_if(cache_.begin(), cache_.end(), [&](const auto &entry) { return entry.file == file && entry.frame == frame; });
    if (cached != cache_.end()) {
      texture_.upload(cached->image); displayed_file_ = file; displayed_frame_ = frame; error_.clear();
      cache_.splice(cache_.begin(), cache_, cached);
    }
  }
  if (file != requested_file_ || frame != requested_frame_) {
    requested_file_ = file; requested_frame_ = frame;
    {
      std::lock_guard lock(decoder_->mutex);
      decoder_->wanted = {file, frame};
      // A cache hit cancels queued work as well as avoiding a redundant decode.
      if (displayed_file_ == file && displayed_frame_ == frame) decoder_->completed = decoder_->wanted;
    }
    decoder_->wake.notify_one();
  }
  if (file.empty() || frame < 0) { ImGui::TextUnformatted("No camera data at this time"); return; }
  if (!error_.empty()) ImGui::TextWrapped("%s", error_.c_str());
  if (texture_.id && displayed_file_ == file) {
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const ImRect bounds(start, ImVec2(start.x + size.x, start.y + size.y));
    const VideoPlacement placement = videoPlacement(bounds, float(texture_.width) / texture_.height, settings.crop_video);
    ImDrawList *draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(start, ImVec2(start.x + size.x, start.y + size.y), IM_COL32(12, 14, 15, 255), 4.f);
    draw->AddImageRounded(texture_.ref(), placement.min, placement.max, placement.uv0, placement.uv1, IM_COL32_WHITE, ImGui::GetStyle().ChildRounding);
    ImGui::Dummy(size);
  } else if (error_.empty()) ImGui::TextUnformatted("Loading camera...");
}
