#pragma once

class DeviceStream;

class JoystickWidget {
public:
  ~JoystickWidget();
  void draw();
  void stop();

private:
  DeviceStream *device_ = nullptr;
  bool armed_ = false;
  bool sending_ = false;
  float limit_ = 1.0f;
  double last_send_ = 0;
};
