#pragma once

class JoystickWidget {
public:
  void draw();
  void stop() { armed_ = false; }

private:
  bool armed_ = false;
  bool sending_ = false;
  float limit_ = 1.0f;
  double last_send_ = 0;
};
