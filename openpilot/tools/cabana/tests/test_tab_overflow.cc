#include <array>
#include <cstdio>
#include <string>

#include "imgui.h"
#include "imgui_internal.h"

#include "common/tests/native_test.h"
#include "tools/cabana/ui/widgets/scrollabletabbar.h"

namespace {
enum class Mode { Widget, DockSpace, Floating };

const char *modeName(Mode mode) {
  switch (mode) {
    case Mode::Widget: return "widget";
    case Mode::DockSpace: return "dockspace";
    case Mode::Floating: return "floating";
  }
  return "unknown";
}

// Exercise real ImGui layout/input without a display or renderer. Floating dock
// groups lay out during NewFrame(), before application tab submission.
class TabOverflowHarness {
public:
  explicit TabOverflowHarness(Mode mode) : mode_(mode) {
    ImGui::CreateContext();
    auto &io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.DisplaySize = ImVec2(1600, 1000);
    io.DeltaTime = 1.f / 60;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    unsigned char *pixels;
    int width, height;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    for (size_t i = 0; i < names_.size(); ++i) names_[i] = "Long analysis tab " + std::to_string(i);

    if (mode_ != Mode::Widget) {
      ImGui::NewFrame();
      ImGui::Begin("Setup");
      dock_id_ = 0xA00 + static_cast<int>(mode_);
      const ImGuiDockNodeFlags flags = mode_ == Mode::DockSpace ? int(ImGuiDockNodeFlags_DockSpace) : int(ImGuiDockNodeFlags_None);
      ImGui::DockBuilderAddNode(dock_id_, flags);
      ImGui::DockBuilderSetNodePos(dock_id_, ImVec2(100, 100));
      ImGui::DockBuilderSetNodeSize(dock_id_, ImVec2(width_, 250));
      for (const auto &name : names_) ImGui::DockBuilderDockWindow(name.c_str(), dock_id_);
      ImGui::DockBuilderFinish(dock_id_);
      ImGui::End();
      ImGui::Render();
    }
  }

  ~TabOverflowHarness() { ImGui::DestroyContext(); }

  void run() {
    frames(6);
    REQUIRE(bar_ && bar_->ScrollButtonEnabled);
    bar_->NextSelectedTabId = bar_->Tabs[0].ID;
    frames(6);
    bar_->ScrollingTarget = bar_->ScrollingAnim = 0;
    const ImGuiID selected = bar_->SelectedTabId;
    auto &io = ImGui::GetIO();
    const float size = ImGui::GetFrameHeight();
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const ImVec2 right_button(bar_->BarRect.Max.x + spacing + size + spacing + size * .5f,
                             bar_->BarRect.Min.y + size * .5f);
    click(right_button);
    const float click_scroll = bar_->ScrollingTarget;
    REQUIRE(click_scroll > 0);
    // Native ImGui arrows select adjacent tabs; shared chevrons only scroll.
    REQUIRE(bar_->SelectedTabId == selected);

    io.AddMousePosEvent(bar_->BarRect.Min.x + 20, bar_->BarRect.Min.y + 5);
    frame();
    io.AddMouseWheelEvent(0, -1);
    frame();
    REQUIRE(bar_->ScrollingTarget > click_scroll);
    REQUIRE(bar_->SelectedTabId == selected);

    bar_->ScrollingTarget = bar_->ScrollingAnim = 0;
    click(ImVec2(right_button.x - size - spacing, right_button.y));
    REQUIRE(bar_->ScrollingTarget == 0);  // Left chevron is disabled at the start.

    io.AddMousePosEvent(right_button.x, right_button.y);
    frame();
    io.AddMouseButtonEvent(0, true);
    frame();
    frames(35);
    io.AddMouseButtonEvent(0, false);
    frame();
    REQUIRE(bar_->ScrollingTarget > click_scroll);  // Holding a chevron repeats.
    REQUIRE(bar_->SelectedTabId == selected);

    resize(1450);
    REQUIRE(!bar_->ScrollButtonEnabled);
    resize(280);
    REQUIRE(bar_->ScrollButtonEnabled);
    printf("Tab overflow: %s passed\n", modeName(mode_));
  }

private:
  void frames(int count) {
    for (int i = 0; i < count; ++i) frame();
  }

  void click(ImVec2 point) {
    auto &io = ImGui::GetIO();
    io.AddMousePosEvent(point.x, point.y);
    frame();
    io.AddMouseButtonEvent(0, true);
    frame();
    io.AddMouseButtonEvent(0, false);
    frame();
  }

  void resize(float width) {
    width_ = width;
    if (mode_ == Mode::Floating) ImGui::DockBuilderSetNodeSize(dock_id_, ImVec2(width_, 250));
    frames(6);
  }

  void frame() {
    ImGui::NewFrame();
    if (mode_ == Mode::Widget) {
      ImGui::SetNextWindowPos(ImVec2(100, 100));
      ImGui::SetNextWindowSize(ImVec2(width_, 250));
      ImGui::Begin("Ordinary", nullptr, ImGuiWindowFlags_NoSavedSettings);
      if (beginScrollableTabBar("tabs")) {
        bar_ = ImGui::GetCurrentTabBar();
        for (const auto &name : names_) {
          if (ImGui::BeginTabItem(name.c_str())) {
            ImGui::TextUnformatted("content");
            ImGui::EndTabItem();
          }
        }
        endScrollableTabBar();
      }
      ImGui::End();
    } else {
      if (mode_ == Mode::DockSpace) {
        ImGui::SetNextWindowPos(ImVec2(100, 100));
        ImGui::SetNextWindowSize(ImVec2(width_, 300));
        ImGui::Begin("Dock host", nullptr, ImGuiWindowFlags_NoSavedSettings);
        ImGui::DockSpace(dock_id_, ImVec2(0, 0));
        ImGui::End();
      }
      for (const auto &name : names_) {
        ImGui::Begin(name.c_str());
        ImGui::TextUnformatted("content");
        ImGui::End();
      }
      auto *node = ImGui::DockBuilderGetNode(dock_id_);
      bar_ = node ? node->TabBar : nullptr;
    }
    ImGui::Render();
  }

  Mode mode_;
  float width_ = 280;
  ImGuiID dock_id_ = 0;
  ImGuiTabBar *bar_ = nullptr;
  std::array<std::string, 6> names_;
};
}  // namespace

int main() {
  return run_native_test([]() {
    for (const Mode mode : {Mode::Widget, Mode::DockSpace, Mode::Floating}) {
      TabOverflowHarness harness(mode);
      harness.run();
    }
  });
}
