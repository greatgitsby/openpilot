// Self-contained multi-camera snapshot for the Titan-170 / Spectra ISP.
//
// This is a standalone replacement for `camerad` for the camera dev loop:
// it brings every camera up through the kernel Spectra stack (cam_req_mgr +
// CSIPHY + CSID/IFE + ICP/BPS + sensor probe over CCI) using openpilot's own,
// hardware-exact bring-up code (SpectraMaster / SpectraCamera), captures a
// handful of frames per camera so auto-exposure settles, writes one image per
// camera, and EXITS. No camerad daemon, no VisionIPC consumer, no manager,
// no params.
//
// Why it exists: on the mainline vamOS kernel the camera bring-up is being
// ported driver-by-driver. Timing a bare `camerad` and grepping dmesg is slow
// and wedges the serial console. This binary gives a single deterministic
// pass/fail: a written JPEG means the kernel took a sensor all the way to
// streaming frames; a clean "sensor N: chip-id NACK / no frame" means it
// didn't. It reuses the EXACT probe path (OS04C10 expects chip id 0x5304), so
// its failure mode is identical to camerad's — but bounded and scriptable.
//
// It still links visionipc/messaging/common because SpectraCamera writes
// frames into a VisionIpcServer's shared-memory buffers; we run that server
// with no subscriber and read the NV12 straight out of the buffer. That keeps
// the reused hardware code byte-identical to camerad.
//
// Output: <out>/snap_<name>.{nv12,png}  (name = wide|road|driver)
// Exit:   0 if every ENABLED camera produced a frame, 1 otherwise.

#include <poll.h>
#include <sys/ioctl.h>

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "media/cam_req_mgr.h"

#include "common/util.h"
#include "common/swaglog.h"
#include "system/camerad/cameras/camera_common.h"
#include "system/camerad/cameras/spectra.h"
#include "system/camerad/cameras/hw.h"

// Number of frames to pump per camera before grabbing, so the IFE/AE pipeline
// has live data. Frame 1 already proves bring-up; a few more give a real image.
static int WARMUP_FRAMES = 8;
// Hard cap on frames to wait before giving up on a camera (bring-up failures
// never reach the warmup count).
static int MAX_FRAMES = 40;

static std::string g_out_dir = "/tmp";

namespace {

const char *stream_name(VisionStreamType t) {
  switch (t) {
    case VISION_STREAM_WIDE_ROAD: return "wide";
    case VISION_STREAM_ROAD:      return "road";
    case VISION_STREAM_DRIVER:    return "driver";
    default:                      return "cam";
  }
}

// Minimal PNG writer (zlib stored/uncompressed blocks) so we have no external
// image dependency. RGB8, no filtering. Small images, this is fine.
uint32_t crc_table[256];
void crc_init() {
  for (uint32_t n = 0; n < 256; n++) {
    uint32_t c = n;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
    crc_table[n] = c;
  }
}
uint32_t crc_update(uint32_t crc, const uint8_t *buf, size_t len) {
  uint32_t c = crc ^ 0xffffffffu;
  for (size_t i = 0; i < len; i++) c = crc_table[(c ^ buf[i]) & 0xff] ^ (c >> 8);
  return c ^ 0xffffffffu;
}
void put_be32(std::vector<uint8_t> &v, uint32_t x) {
  v.push_back(x >> 24); v.push_back(x >> 16); v.push_back(x >> 8); v.push_back(x);
}
void png_chunk(std::vector<uint8_t> &out, const char *type, const std::vector<uint8_t> &data) {
  put_be32(out, data.size());
  size_t crc_start = out.size();
  out.insert(out.end(), type, type + 4);
  out.insert(out.end(), data.begin(), data.end());
  uint32_t crc = crc_update(0, out.data() + crc_start, 4 + data.size());
  put_be32(out, crc);
}
uint32_t adler32(const uint8_t *data, size_t len) {
  uint32_t a = 1, b = 0;
  for (size_t i = 0; i < len; i++) { a = (a + data[i]) % 65521; b = (b + a) % 65521; }
  return (b << 16) | a;
}
bool write_png(const std::string &fn, const uint8_t *rgb, int w, int h) {
  // Build raw scanlines with filter byte 0.
  std::vector<uint8_t> raw;
  raw.reserve((size_t)h * (1 + w * 3));
  for (int y = 0; y < h; y++) {
    raw.push_back(0);
    raw.insert(raw.end(), rgb + (size_t)y * w * 3, rgb + (size_t)(y + 1) * w * 3);
  }
  // zlib wrapper around stored deflate blocks.
  std::vector<uint8_t> z;
  z.push_back(0x78); z.push_back(0x01);
  size_t off = 0;
  while (off < raw.size()) {
    size_t n = std::min<size_t>(65535, raw.size() - off);
    z.push_back(off + n >= raw.size() ? 1 : 0);  // BFINAL
    z.push_back(n & 0xff); z.push_back((n >> 8) & 0xff);
    z.push_back(~n & 0xff); z.push_back((~n >> 8) & 0xff);
    z.insert(z.end(), raw.begin() + off, raw.begin() + off + n);
    off += n;
  }
  put_be32(z, adler32(raw.data(), raw.size()));

  std::vector<uint8_t> out = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
  std::vector<uint8_t> ihdr;
  put_be32(ihdr, w); put_be32(ihdr, h);
  ihdr.push_back(8); ihdr.push_back(2); ihdr.push_back(0); ihdr.push_back(0); ihdr.push_back(0);
  png_chunk(out, "IHDR", ihdr);
  png_chunk(out, "IDAT", z);
  png_chunk(out, "IEND", {});

  FILE *f = fopen(fn.c_str(), "wb");
  if (!f) return false;
  fwrite(out.data(), 1, out.size(), f);
  fclose(f);
  return true;
}

// NV12 -> RGB (BT.601-ish, matching snapshot.py's matrix).
void nv12_to_rgb(const VisionBuf *b, std::vector<uint8_t> &rgb) {
  const int w = (int)b->width, h = (int)b->height, stride = (int)b->stride;
  const uint8_t *y = (const uint8_t *)b->y;
  const uint8_t *uv = (const uint8_t *)b->uv;
  rgb.resize((size_t)w * h * 3);
  for (int j = 0; j < h; j++) {
    for (int i = 0; i < w; i++) {
      int Y = y[j * stride + i];
      int U = uv[(j / 2) * stride + (i & ~1) + 0] - 128;
      int V = uv[(j / 2) * stride + (i & ~1) + 1] - 128;
      int R = Y + (1.13983f * V);
      int G = Y - (0.39465f * U) - (0.58060f * V);
      int B = Y + (2.03211f * U);
      uint8_t *p = &rgb[((size_t)j * w + i) * 3];
      p[0] = std::clamp(R, 0, 255);
      p[1] = std::clamp(G, 0, 255);
      p[2] = std::clamp(B, 0, 255);
    }
  }
}

}  // namespace

int main(int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--out" && i + 1 < argc) g_out_dir = argv[++i];
    else if (a == "--warmup" && i + 1 < argc) WARMUP_FRAMES = atoi(argv[++i]);
    else if (a == "--max-frames" && i + 1 < argc) MAX_FRAMES = atoi(argv[++i]);
    else if (a == "--help") {
      printf("usage: %s [--out DIR] [--warmup N] [--max-frames N]\n", argv[0]);
      printf("  brings up all cameras via the Spectra stack, writes one image each, exits.\n");
      return 0;
    }
  }
  crc_init();

  // VisionIpcServer with no consumer: it just owns the shared-mem YUV buffers
  // that SpectraCamera fills. We read frames straight out of them.
  VisionIpcServer v("camerad");

  SpectraMaster m;
  m.init();

  std::vector<std::unique_ptr<SpectraCamera>> cams;
  for (const auto &config : ALL_CAMERA_CONFIGS) {
    auto cam = std::make_unique<SpectraCamera>(&m, config);
    cam->camera_open(&v);
    cams.emplace_back(std::move(cam));
  }
  v.start_listener();

  LOG("-- starting devices");
  for (auto &cam : cams) {
    if (cam->enabled) cam->sensors_start();
  }

  // Per-camera capture state.
  std::map<int32_t, int> frame_count;       // session_handle -> frames seen
  std::map<int32_t, bool> captured;         // session_handle -> wrote image
  int n_enabled = 0, n_captured = 0;
  for (auto &cam : cams) if (cam->enabled) n_enabled++;

  LOG("-- dequeueing video events (%d enabled cameras)", n_enabled);
  int idle_polls = 0;
  while (n_captured < n_enabled && idle_polls < 20) {
    struct pollfd fds[1] = {{.fd = m.video0_fd, .events = POLLPRI}};
    int ret = poll(fds, 1, 1000);
    if (ret < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      LOGE("poll failed (%d - %d)", ret, errno);
      break;
    }
    if (ret == 0) { idle_polls++; continue; }
    if (!(fds[0].revents & POLLPRI)) continue;
    idle_polls = 0;

    struct v4l2_event ev = {0};
    if (HANDLE_EINTR(ioctl(fds[0].fd, VIDIOC_DQEVENT, &ev)) != 0) {
      LOGE("VIDIOC_DQEVENT failed, errno=%d", errno);
      continue;
    }
    if (ev.type != V4L_EVENT_CAM_REQ_MGR_EVENT) continue;

    auto *event_data = (struct cam_req_mgr_message *)ev.u.data;
    for (auto &cam : cams) {
      if (!cam->enabled) continue;
      if (event_data->session_hdl != cam->session_handle) continue;
      if (captured[cam->session_handle]) break;

      if (cam->handle_camera_event(event_data)) {
        int fc = ++frame_count[cam->session_handle];
        const char *nm = stream_name(cam->cc.stream_type);
        if (fc == 1) LOG("cam %s: first frame (bring-up OK)", nm);

        if (fc >= WARMUP_FRAMES || fc >= MAX_FRAMES) {
          // Populate cur_yuv_buf from the latest IFE buffer, then read it.
          cam->buf.sendFrameToVipc();
          VisionBuf *yuv = cam->buf.cur_yuv_buf;

          std::string base = g_out_dir + "/snap_" + nm;
          // raw NV12 dump (always — survives even if PNG conv is suspect)
          if (FILE *f = fopen((base + ".nv12").c_str(), "wb")) {
            fwrite(yuv->addr, 1, yuv->len, f);
            fclose(f);
          }
          std::vector<uint8_t> rgb;
          nv12_to_rgb(yuv, rgb);
          bool ok = write_png(base + ".png", rgb.data(), (int)yuv->width, (int)yuv->height);
          LOG("cam %s: captured %zux%zu frame_id=%u -> %s.png%s", nm,
              yuv->width, yuv->height, cam->buf.cur_frame_data.frame_id,
              base.c_str(), ok ? "" : " (PNG WRITE FAILED)");
          captured[cam->session_handle] = true;
          n_captured++;
        }
      }
      break;
    }
  }

  printf("\n=== captured %d/%d cameras ===\n", n_captured, n_enabled);
  for (auto &cam : cams) {
    if (!cam->enabled) continue;
    const char *nm = stream_name(cam->cc.stream_type);
    printf("  %-6s: %s (%d frames)\n", nm,
           captured[cam->session_handle] ? "OK" : "NO FRAME (bring-up failed)",
           frame_count[cam->session_handle]);
  }
  return (n_captured == n_enabled && n_enabled > 0) ? 0 : 1;
}
