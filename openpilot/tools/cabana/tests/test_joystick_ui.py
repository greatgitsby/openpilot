import pathlib
import subprocess
import tempfile
import unittest

import imgui

ROOT = pathlib.Path(__file__).resolve().parents[4]

FAKE_DEVICESTREAM = """
#pragma once
#include <array>
#include <vector>
struct AbstractStream { virtual ~AbstractStream() = default; };
struct DeviceStream : AbstractStream {
  std::vector<std::array<float, 2>> sent;
  bool remote() const { return true; }
  void sendJoystick(float gas, float steer) { sent.push_back({gas, steer}); }
};
extern AbstractStream *can;
"""

TEST = r"""
#include <cassert>
#include "imgui.h"
#include "tools/cabana/streams/devicestream.h"
#include "tools/cabana/ui/widgets/joystickwidget.h"

AbstractStream *can;

int main() {
  ImGui::CreateContext();
  auto &io = ImGui::GetIO();
  io.IniFilename = nullptr;
  io.ConfigInputTrickleEventQueue = false;  // apply each frame's input events in that frame
  io.DisplaySize = ImVec2(640, 640);
  io.DeltaTime = 0.06f;  // every frame is due to send
  unsigned char *pixels;
  int width, height;
  io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
  DeviceStream device;
  can = &device;
  JoystickWidget widget;
  ImVec2 readout;
  auto frame = [&]() {
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(400, 600));
    ImGui::Begin("Joystick", nullptr, ImGuiWindowFlags_NoTitleBar);
    widget.draw();
    readout = ImGui::GetItemRectMin();
    ImGui::End();
    ImGui::Render();
  };
  auto sent = [&](float gas, float steer) { return device.sent.back()[0] == gas && device.sent.back()[1] == steer; };

  frame();
  frame();  // a new window takes two frames to become hoverable
  assert(device.sent.empty());
  io.AddMousePosEvent(15, 17);  // arm
  io.AddMouseButtonEvent(0, true);
  frame();
  io.AddMouseButtonEvent(0, false);
  frame();
  io.AddKeyEvent(ImGuiKey_W, true);
  io.AddKeyEvent(ImGuiKey_A, true);
  frame();
  assert(sent(1, 1));
  io.AddKeyEvent(ImGuiKey_W, false);
  io.AddKeyEvent(ImGuiKey_A, false);
  frame();
  assert(sent(0, 0));

  // the 240px pad is above the readout, the mouse outputs at least 0.2 per displaced axis
  const float top = readout.y - ImGui::GetStyle().ItemSpacing.y - 240;
  io.AddMousePosEvent(129, top + 119);
  io.AddMouseButtonEvent(0, true);
  frame();
  assert(sent(0.2f, -0.2f));
  io.AddMousePosEvent(248, top);
  frame();
  assert(sent(1, -1));
  io.AddMouseButtonEvent(0, false);
  frame();
  assert(sent(0, 0));

  // focus loss disarms with a centered command
  io.AddKeyEvent(ImGuiKey_S, true);
  frame();
  assert(sent(-1, 0));
  io.AddFocusEvent(false);
  frame();
  assert(sent(0, 0));
  const size_t count = device.sent.size();
  io.AddFocusEvent(true);
  frame();
  assert(device.sent.size() == count);
}
"""


class TestJoystickUi(unittest.TestCase):
  def test_keyboard_mouse_and_focus(self):
    with tempfile.TemporaryDirectory() as directory:
      tmp = pathlib.Path(directory)
      header = tmp / "tools/cabana/streams/devicestream.h"
      header.parent.mkdir(parents=True)
      header.write_text(FAKE_DEVICESTREAM)
      (tmp / "test.cc").write_text(TEST)
      subprocess.run(["c++", "-std=c++20", f"-I{tmp}", f"-I{ROOT / 'openpilot'}", f"-I{imgui.INCLUDE_DIR}", str(tmp / "test.cc"),
                      str(ROOT / "openpilot/tools/cabana/ui/widgets/joystickwidget.cc"), str(pathlib.Path(imgui.LIB_DIR) / "libimgui.a"),
                      "-o", str(tmp / "test")], check=True, timeout=60)
      subprocess.run([str(tmp / "test")], check=True, timeout=30)


if __name__ == "__main__":
  unittest.main()
