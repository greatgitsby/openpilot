#include "tools/cabana/ui/widgets/joystickwidget.h"

#include <algorithm>
#include <cmath>

#include "imgui.h"
#include "tools/cabana/streams/devicestream.h"

void JoystickWidget::draw() {
  auto *device = dynamic_cast<DeviceStream *>(can);
  if (!device || !device->remote()) {
    stop();
    ImGui::TextWrapped("Open a device WebRTC stream to drive a comma body.");
    return;
  }
  const auto &io = ImGui::GetIO();
  if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) || io.AppFocusLost || ImGui::IsKeyPressed(ImGuiKey_Escape)) stop();
  ImGui::Checkbox("Arm controls", &armed_);
  ImGui::SliderFloat("Output limit", &limit_, 0.05f, 1.0f, "%.2f");
  ImGui::TextWrapped("Drives a comma body. Hold W/S for gas/brake, A/D for steering, or drag the pad. Release to center. Escape disarms.");

  const float size = std::clamp(ImGui::GetContentRegionAvail().x, 80.0f, 240.0f), radius = size / 2;
  const ImVec2 pos = ImGui::GetCursorScreenPos(), center(pos.x + radius, pos.y + radius);
  ImGui::InvisibleButton("joystick_pad", ImVec2(size, size));
  float gas = 0, steer = 0;
  if (armed_ && ImGui::IsItemActive()) {
    // Like Connect, a displaced mouse axis outputs at least 0.2.
    auto axis = [&](float offset) {
      const float value = std::clamp(offset / radius, -1.0f, 1.0f);
      return value == 0 ? 0.0f : std::copysign(std::max(std::abs(value), 0.2f), value);
    };
    gas = axis(center.y - io.MousePos.y);
    steer = axis(center.x - io.MousePos.x);
  } else if (armed_ && !io.WantTextInput && !ImGui::IsAnyItemActive()) {
    gas = ImGui::IsKeyDown(ImGuiKey_W) - ImGui::IsKeyDown(ImGuiKey_S);
    steer = ImGui::IsKeyDown(ImGuiKey_A) - ImGui::IsKeyDown(ImGuiKey_D);
  }

  auto *draw = ImGui::GetWindowDrawList();
  draw->AddRectFilled(pos, ImVec2(pos.x + size, pos.y + size), ImGui::GetColorU32(ImGuiCol_FrameBg), 8);
  draw->AddLine(ImVec2(center.x, pos.y), ImVec2(center.x, pos.y + size), ImGui::GetColorU32(ImGuiCol_Border));
  draw->AddLine(ImVec2(pos.x, center.y), ImVec2(pos.x + size, center.y), ImGui::GetColorU32(ImGuiCol_Border));
  draw->AddCircleFilled(ImVec2(center.x - steer * (radius - 12), center.y - gas * (radius - 12)), 12,
                        ImGui::GetColorU32(armed_ ? ImGuiCol_SliderGrabActive : ImGuiCol_TextDisabled));
  ImGui::Text("Gas / brake: %+.2f   Steering: %+.2f", gas * limit_, steer * limit_);

  // 20 Hz while armed, then one centered command. The body also stops by itself when commands stop.
  if ((armed_ || sending_) && ImGui::GetTime() - last_send_ >= 0.05) {
    device->sendJoystick(gas * limit_, steer * limit_);
    sending_ = armed_;
    last_send_ = ImGui::GetTime();
  }
}
