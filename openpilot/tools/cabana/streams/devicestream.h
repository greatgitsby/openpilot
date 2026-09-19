#pragma once

#include "tools/cabana/streams/livestream.h"

#include <string>
#include <sys/types.h>

class DeviceStream : public LiveStream {
public:
  DeviceStream(std::string dongle_id = {});
  ~DeviceStream();
  std::string routeName() const override {
    return remote() ? "WebRTC From " + dongle_id_ : "Local CAN";
  }
  bool remote() const { return !dongle_id_.empty(); }
  const std::string &cameraServer() const { return camera_server_; }

protected:
  void start() override;
  void streamThread() override;
  void stopBridge();
  bool readPipe(void *data, size_t size);
  pid_t bridge_pid = -1;
  int bridge_fd_ = -1;
  const std::string dongle_id_;
  const std::string camera_server_;
};
