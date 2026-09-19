#pragma once

class JoystickWidget {
public:
  ~JoystickWidget();
  void draw();
  void stop();

private:
  bool armed_ = false;
  bool sending_ = false;
  float limit_ = 1.0f;
  double last_send_ = 0;
};
