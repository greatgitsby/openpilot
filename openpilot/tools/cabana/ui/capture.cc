#include "tools/cabana/ui/capture.h"
#include <algorithm>
#include <fstream>
#include <stdexcept>
extern "C" {
#include <libavcodec/avcodec.h>
}
void saveCapture(const std::string &path, int width, int height, const std::vector<uint8_t> &pixels) {
  const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_PNG);
  AVCodecContext *context = codec ? avcodec_alloc_context3(codec) : nullptr;
  AVFrame *frame = av_frame_alloc(); AVPacket *packet = av_packet_alloc();
  bool success = false;
  if (context && frame && packet && width > 0 && height > 0 && pixels.size() == size_t(width) * height * 4) {
    context->width = width; context->height = height; context->pix_fmt = AV_PIX_FMT_RGBA; context->time_base = {1, 1};
    frame->width = width; frame->height = height; frame->format = AV_PIX_FMT_RGBA;
    if (avcodec_open2(context, codec, nullptr) >= 0 && av_frame_get_buffer(frame, 0) >= 0) {
      for (int y = 0; y < height; ++y) std::copy_n(pixels.data() + size_t(height - y - 1) * width * 4, width * 4, frame->data[0] + y * frame->linesize[0]);
      if (avcodec_send_frame(context, frame) >= 0 && avcodec_receive_packet(context, packet) >= 0) {
        std::ofstream file(path, std::ios::binary); file.write((char *)packet->data, packet->size); success = bool(file);
      }
    }
  }
  av_packet_free(&packet); av_frame_free(&frame); avcodec_free_context(&context);
  if (!success) throw std::runtime_error("Could not save PNG: " + path);
}
