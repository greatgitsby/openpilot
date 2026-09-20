import pathlib
import subprocess
import tempfile
import unittest

import imgui


class TestJoystickUi(unittest.TestCase):
  def test_keyboard_mouse_and_focus(self):
    with tempfile.TemporaryDirectory(prefix="cabana-joystick-ui-") as directory:
      root = pathlib.Path(__file__).resolve().parents[4]
      tmp = pathlib.Path(directory)
      h = tmp / 'tools/cabana/streams/devicestream.h'
      h.parent.mkdir(parents=True)
      h.write_text('''#pragma once
      #include <string>
      #include <vector>
      #include <array>
      struct AbstractStream { virtual ~AbstractStream() = default; };
      struct DeviceStream : AbstractStream {
       bool joystick_ready=true; std::string joystick_status;
       std::vector<std::array<float, 2>> sent;
       bool remote() const { return true; }
       bool sendJoystick(float gas,float steer,bool cancel=false) { sent.push_back({gas,steer}); return true; }
       void setJoystickMode(bool mode) { joystick_ready=mode; }
      };
      extern AbstractStream *can;
      ''')
      (tmp/'test.cc').write_text(r'''
      #include <cassert>
      #include <cstdio>
      #include "imgui.h"
      #include "tools/cabana/streams/devicestream.h"
      #include "tools/cabana/ui/widgets/joystickwidget.h"
      AbstractStream *can;
      int main() {
       ImGui::CreateContext(); auto &io=ImGui::GetIO(); io.IniFilename=nullptr;
       io.DisplaySize=ImVec2(640,640); io.DeltaTime=0.06f;
       unsigned char *pixels; int w,h; io.Fonts->GetTexDataAsRGBA32(&pixels,&w,&h);
       DeviceStream device;can=&device;JoystickWidget widget; ImVec2 last;
       auto frame=[&]() {
        ImGui::NewFrame(); ImGui::SetNextWindowPos(ImVec2(0,0)); ImGui::SetNextWindowSize(ImVec2(400,600));
        ImGui::Begin("Joystick",nullptr,ImGuiWindowFlags_NoTitleBar);widget.draw();last=ImGui::GetItemRectMin();
        ImGui::End();ImGui::Render();
       };
       frame();frame();
       auto click=[&](float x,float y) {io.AddMousePosEvent(x,y);io.AddMouseButtonEvent(0,true);frame();io.AddMouseButtonEvent(0,false);frame();};
       click(15,40); // arm
       assert(!device.sent.empty());
       io.AddKeyEvent(ImGuiKey_W,true);frame(); assert(device.sent.back()[0]==1.0f);
       io.AddKeyEvent(ImGuiKey_A,true);frame(); assert(device.sent.back()[1]==1.0f);
       io.AddKeyEvent(ImGuiKey_W,false);io.AddKeyEvent(ImGuiKey_A,false);frame();assert(device.sent.back()[0]==0 && device.sent.back()[1]==0);
       // The readout immediately follows the 240px pad.
       float pad_y=last.y-ImGui::GetStyle().ItemSpacing.y-240;
       io.AddMousePosEvent(128,pad_y+12);io.AddMouseButtonEvent(0,true);frame();assert(device.sent.back()[0]>0.8f);
       io.AddMousePosEvent(129,pad_y+119);frame();
       assert(device.sent.back()[0]==0.20f && device.sent.back()[1]==-0.20f);
       io.AddMousePosEvent(128,pad_y+120);frame();
       assert(device.sent.back()[0]==0 && device.sent.back()[1]==0);
       io.AddMousePosEvent(248,pad_y);frame();
       assert(device.sent.back()[0]==1 && device.sent.back()[1]==-1);
       io.AddMouseButtonEvent(0,false);frame();assert(device.sent.back()[0]==0);
       io.AddKeyEvent(ImGuiKey_S,true);frame();assert(device.sent.back()[0]==-1.0f);
       io.AddFocusEvent(false);frame();assert(device.sent.back()[0]==0);
       auto count=device.sent.size();io.AddFocusEvent(true);frame();assert(device.sent.size()==count); // must rearm
       io.AddKeyEvent(ImGuiKey_S,false);frame();click(15,40);io.AddKeyEvent(ImGuiKey_D,true);frame();assert(device.sent.back()[1]==-1.0f);
       DeviceStream other; can=&other;frame();
       assert(device.sent.back()[1]==0 && other.sent.empty()); // source switch centers the old device and disarms
       can=&device;frame();click(15,40);frame();assert(device.sent.back()[1]==-1.0f);
       widget.stop();assert(device.sent.back()[1]==0); // hidden/closed dock
       puts("PASS: keyboard axes, mouse pad, release-to-center, focus loss, rearm, dock close");
      }
      ''')
      subprocess.run(['c++', '-std=c++20', '-I'+str(tmp), '-I'+str(root/'openpilot'), '-I'+str(imgui.INCLUDE_DIR), str(tmp/'test.cc'),
                      str(root/'openpilot/tools/cabana/ui/widgets/joystickwidget.cc'), str(pathlib.Path(imgui.LIB_DIR)/'libimgui.a'),
                      '-o', str(tmp/'test')], check=True, timeout=30)
      subprocess.run([str(tmp/'test')], check=True, timeout=30)


if __name__ == "__main__":
  unittest.main()
