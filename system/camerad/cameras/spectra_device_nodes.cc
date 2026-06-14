#include "system/camerad/cameras/spectra_device_nodes.h"

#include <string>
#include <vector>

#include "common/util.h"
#include "common/swaglog.h"

int open_v4l_video_by_name(const char *name, const char *by_path_fallback, int flags) {
  std::vector<std::string> discovered;  // "videoN <name>" for failure logging

  for (int idx = 0; /**/; ++idx) {
    std::string node_name = util::read_file(
        util::string_format("/sys/class/video4linux/video%d/name", idx));
    if (node_name.empty()) break;  // no more video nodes

    // names often carry a trailing newline
    while (!node_name.empty() && (node_name.back() == '\n' || node_name.back() == '\r')) {
      node_name.pop_back();
    }
    discovered.push_back(util::string_format("video%d %s", idx, node_name.c_str()));

    if (node_name.find(name) == 0) {
      std::string dev = util::string_format("/dev/video%d", idx);
      int fd = HANDLE_EINTR(open(dev.c_str(), flags));
      LOGD("camera node '%s' -> %s (fd %d)", name, dev.c_str(), fd);
      return fd;
    }
  }

  // Fall back to the legacy by-path string before giving up.
  if (by_path_fallback != nullptr) {
    int fd = HANDLE_EINTR(open(by_path_fallback, flags));
    if (fd >= 0) {
      LOGW("camera node '%s' not found by name; using fallback %s (fd %d)",
           name, by_path_fallback, fd);
      return fd;
    }
  }

  LOGE("camera node '%s' not found. discovered video nodes:", name);
  for (const auto &d : discovered) {
    LOGE("  %s", d.c_str());
  }
  return -1;
}
