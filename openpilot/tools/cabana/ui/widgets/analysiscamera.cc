#include "tools/cabana/ui/widgets/analysiscamera.h"
#include "common/yuv.h"

struct AnalysisCamera::Decoder {
  std::unique_ptr<FrameReader> reader;
  std::string file;
  std::atomic<bool> abort = false;
  std::vector<uint8_t> bytes;
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
AnalysisCamera::AnalysisCamera() : decoder_(std::make_shared<Decoder>()) {}
AnalysisCamera::~AnalysisCamera() { decoder_->abort = true; }
void AnalysisCamera::draw(const std::string &file, int frame, const ImVec2 &size) {
  if (pending_.valid() && pending_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
    try {
      auto image = pending_.get();
      if (!image.isNull()) { texture_.upload(image); displayed_file_ = requested_file_; displayed_frame_ = requested_frame_; error_.clear(); }
    } catch (const std::exception &e) { error_ = e.what(); }
  }
  if (!pending_.valid() && !file.empty() && frame >= 0 && (file != requested_file_ || frame != requested_frame_)) {
    requested_file_ = file; requested_frame_ = frame;
    pending_ = std::async(std::launch::async, [decoder = decoder_, file, frame]() { return decoder->get(file, frame); });
  }
  if (file.empty() || frame < 0) { ImGui::TextUnformatted("No camera data at this time"); return; }
  if (!error_.empty()) ImGui::TextWrapped("%s", error_.c_str());
  if (texture_.id) {
    float scale = std::min(size.x / texture_.width, size.y / texture_.height);
    ImGui::Image(texture_.ref(), ImVec2(texture_.width * scale, texture_.height * scale));
  } else if (error_.empty()) ImGui::TextUnformatted("Loading camera...");
}
