#include "tools/cabana/ui/util.h"
#include "tools/cabana/ui/icons.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include <GLFW/glfw3.h>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <climits>

void near(float a, float b) { if (std::abs(a-b) >= 1.1f) { fprintf(stderr,"near failed: %f vs %f\n",a,b); abort(); } }
int main() {
  assert(glfwInit());
  auto *window = glfwCreateWindow(1000,700,"Spacing geometry checks",nullptr,nullptr); assert(window);
  glfwMakeContextCurrent(window);
  ImGui::CreateContext(); ImPlot::CreateContext();
  ImGui_ImplGlfw_InitForOpenGL(window,true); ImGui_ImplOpenGL3_Init(); loadFonts();
  ImGui::GetIO().IniFilename=nullptr;
  for (int theme : {1,2}) for (float scale : {1.0f,1.5f,2.0f}) {
    applyTheme(theme); ImGui::GetStyle().ScaleAllSizes(scale);
    for (int frame=0;frame<3;++frame) {
      glfwPollEvents(); ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();
      ImGui::SetNextWindowPos({0,0}); ImGui::SetNextWindowSize({1000,700}); ImGui::Begin("check",nullptr,ImGuiWindowFlags_NoDecoration);
      auto &style=ImGui::GetStyle();
      std::vector<ImRect> rects;
      std::vector<ToolbarItem> items;
      for (int i=0;i<4;++i) items.push_back({iconButtonWidth(),[&,i] {
        ImGui::PushID(i); iconButton("button",icon::PLUS_LG); rects.emplace_back(ImGui::GetItemRectMin(),ImGui::GetItemRectMax()); ImGui::PopID();
      }});
      const float width=toolbarWidth(items,items.size());
      drawToolbar(items,items.size(),width);
      assert(rects.size()==4);
      for (int i=1;i<4;++i) near(rects[i].Min.x-rects[i-1].Max.x,style.ItemSpacing.x);
      near(rects.back().Max.x-rects.front().Min.x,width);
      rects.clear();
      drawToolbar(items,items.size(),iconButtonWidth()*3+style.ItemSpacing.x*2);
      assert(rects.size()==2); // third slot is the overflow button
      near(ImGui::GetItemRectMax().x-ImGui::GetCursorStartPos().x,iconButtonWidth()*3+style.ItemSpacing.x*2);
      std::string text="123"; ImGui::SetNextItemWidth(240); clearableInput("##clearable",&text);
      near(ImGui::GetItemRectSize().x,240);
      int value=64; auto inner=style.ItemInnerSpacing;
      ImGui::SetNextItemWidth(inputIntWidth(2)); inputInt("##number",&value);
      near(ImGui::GetItemRectSize().x,inputIntWidth(2)); near(style.ItemInnerSpacing.x,inner.x);
      bool ok=false,cancel=false;
      dialogButtons("Accept this longer label",&ok,&cancel);
      assert(ImGui::GetItemRectSize().x>=toolbarButtonWidth("Accept this longer label")-1);
      near(ImGui::GetItemRectMax().x,ImGui::GetWindowPos().x+ImGui::GetWindowContentRegionMax().x);
      ImGui::End(); ImGui::Render();
      glViewport(0,0,1000,700); glClear(GL_COLOR_BUFFER_BIT); ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData()); glfwSwapBuffers(window);
    }
  }
  applyTheme(1);
  int value = 8;
  ImGuiInputTextFlags flags = ImGuiInputTextFlags_None;
  ImRect rect;
  ImVec2 mouse(-100,-100);
  auto frame = [&]() {
    glfwPollEvents(); ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame();
    ImGui::GetIO().AddMousePosEvent(mouse.x,mouse.y);
    ImGui::GetIO().DeltaTime = 1.0f / 60;
    ImGui::NewFrame();
    ImGui::SetNextWindowPos({0,0}); ImGui::SetNextWindowSize({1000,700});
    ImGui::Begin("input behavior",nullptr,ImGuiWindowFlags_NoDecoration);
    ImGui::SetNextItemWidth(200);
    bool changed = inputInt("##number", &value, 1, 100, flags);
    rect = ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
    ImGui::End(); ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    return changed;
  };
  frame(); frame();
  auto click = [&](bool increment, int held_frames = 1) {
    ImVec2 center(rect.Max.x - iconButtonWidth() / 2, rect.GetCenter().y);
    if (!increment) center.x -= iconButtonWidth() + ImGui::GetStyle().ItemSpacing.x;
    mouse = center; frame(); frame();
    ImGui::GetIO().AddMouseButtonEvent(0,true);
    bool changed = false;
    for (int i=0;i<held_frames;++i) changed |= frame();
    ImGui::GetIO().AddMouseButtonEvent(0,false); changed |= frame();
    return changed;
  };
  { bool changed = click(true); fprintf(stderr,"increment changed=%d value=%d\n",changed,value); assert(changed && value == 9); }
  { bool changed = click(false); fprintf(stderr,"decrement changed=%d value=%d\n",changed,value); assert(changed && value == 8); }
  ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl,true); frame();
  assert(click(true) && value == 108);
  ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl,false); frame();
  assert(click(false,40) && value < 107); // holding repeats
  flags = ImGuiInputTextFlags_ReadOnly;
  const int readonly_value = value;
  assert(!click(true) && value == readonly_value);
  flags = ImGuiInputTextFlags_None;
  value = INT_MAX; assert(!click(true) && value == INT_MAX);
  value = INT_MIN; assert(!click(false) && value == INT_MIN);
  value = 8;
  mouse = ImVec2(rect.Min.x + 20,rect.GetCenter().y); frame(); frame();
  ImGui::GetIO().AddMouseButtonEvent(0,true); frame();
  ImGui::GetIO().AddMouseButtonEvent(0,false); frame();
  ImGui::GetIO().AddInputCharactersUTF8("42"); frame(); frame();
  fprintf(stderr,"typed value=%d active=%u\n",value,ImGui::GetActiveID());
  assert(value == 42);
  ImGui::GetIO().AddKeyEvent(ImGuiKey_Enter,true); frame();
  ImGui::GetIO().AddKeyEvent(ImGuiKey_Enter,false); frame();
  assert(value == 42);
  ImGui::GetIO().AddMouseButtonEvent(0,true); frame();
  ImGui::GetIO().AddMouseButtonEvent(0,false); frame();
  ImGui::GetIO().AddInputCharactersUTF8("99"); frame();
  assert(value == 99);
  ImGui::GetIO().AddKeyEvent(ImGuiKey_Escape,true); frame();
  ImGui::GetIO().AddKeyEvent(ImGuiKey_Escape,false); frame();
  assert(value == 42);
  puts("PASS: keyboard entry, Enter commit, Escape restoration.");
  puts("PASS: numeric increment/decrement, Ctrl fast step, hold repeat, read-only, overflow saturation.");
  puts("PASS: equal toolbar gaps, overflow reservation, clearable input width, numeric width/style restoration, long dialog labels; light/dark at 1x, 1.5x, 2x.");
}
