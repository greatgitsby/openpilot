#include "tools/cabana/ui/widgets/joystickwidget.h"

#include <algorithm>
#include <cmath>

#include "imgui.h"
#include "tools/cabana/streams/devicestream.h"

JoystickWidget::~JoystickWidget() { stop(); }

void JoystickWidget::stop() {
  if (sending_) {
    if (auto *device = dynamic_cast<DeviceStream *>(can)) device->sendJoystick(0, 0);
  }
  armed_ = sending_ = false;
}

void JoystickWidget::draw() {
  auto *device = dynamic_cast<DeviceStream *>(can);
  if (!device || !device->remote()) {
    stop();
    ImGui::TextWrapped("Open a device WebRTC stream to use joystick controls.");
    return;
  }
  bool mode = device->joystick_ready;
  if (ImGui::Checkbox("Device joystick mode", &mode)) {
    stop();
    device->setJoystickMode(mode);
  }
  if (!device->joystick_status.empty()) ImGui::TextWrapped("%s", device->joystick_status.c_str());
  if (!device->joystick_ready) {
    stop();
    ImGui::TextWrapped("Enable joystick mode while the car is off, then start the car.");
    return;
  }
  if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) || ImGui::GetIO().AppFocusLost) stop();
  ImGui::Checkbox("Arm controls", &armed_);
  ImGui::SliderFloat("Output limit", &limit_, 0.05f, 1.0f, "%.2f");
  ImGui::TextWrapped("Hold W/S for gas/brake, A/D for steering, or drag the pad. Release to center. Escape disarms.");
  const float size = std::clamp(ImGui::GetContentRegionAvail().x, 80.0f, 240.0f);
  const ImVec2 pos = ImGui::GetCursorScreenPos();
  const ImVec2 center(pos.x + size / 2, pos.y + size / 2);
  ImGui::InvisibleButton("joystick_pad", ImVec2(size, size));
  float gas = 0, steer = 0;
  const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().AppFocusLost;
  if (!focused || ImGui::IsKeyPressed(ImGuiKey_Escape)) stop();
  if (armed_ && focused) {
    if (ImGui::IsItemActive() && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
      gas = std::clamp((center.y - ImGui::GetIO().MousePos.y) / (size / 2), -1.0f, 1.0f);
      steer = std::clamp((center.x - ImGui::GetIO().MousePos.x) / (size / 2), -1.0f, 1.0f);
      // Match Connect's minimum output for a displaced mouse axis.
      const auto mouse_output = [](float value) {
        return value == 0 ? 0.0f : std::copysign(std::max(std::abs(value), 0.20f), value);
      };
      gas = mouse_output(gas);
      steer = mouse_output(steer);
    } else if (!ImGui::GetIO().WantTextInput && !ImGui::IsAnyItemActive()) {
      gas = (float)ImGui::IsKeyDown(ImGuiKey_W) - (float)ImGui::IsKeyDown(ImGuiKey_S);
      steer = (float)ImGui::IsKeyDown(ImGuiKey_A) - (float)ImGui::IsKeyDown(ImGuiKey_D);
    }
  }
  auto *draw = ImGui::GetWindowDrawList();
  draw->AddRectFilled(pos, ImVec2(pos.x + size, pos.y + size), ImGui::GetColorU32(ImGuiCol_FrameBg), 8);
  draw->AddLine(ImVec2(center.x, pos.y), ImVec2(center.x, pos.y + size), ImGui::GetColorU32(ImGuiCol_Border));
  draw->AddLine(ImVec2(pos.x, center.y), ImVec2(pos.x + size, center.y), ImGui::GetColorU32(ImGuiCol_Border));
  draw->AddCircleFilled(ImVec2(center.x - steer * (size / 2 - 12), center.y - gas * (size / 2 - 12)), 12,
                        ImGui::GetColorU32(armed_ ? ImGuiCol_SliderGrabActive : ImGuiCol_TextDisabled));
  ImGui::Text("Gas / brake: %+.2f   Steering: %+.2f", gas * limit_, steer * limit_);
  if (!armed_) {
    stop();
  } else if (ImGui::GetTime() - last_send_ >= 0.05) {
    if (!device->sendJoystick(gas * limit_, steer * limit_)) stop();
    else sending_ = true;
    last_send_ = ImGui::GetTime();
  }
}
