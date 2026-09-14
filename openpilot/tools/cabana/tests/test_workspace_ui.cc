#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include <capnp/message.h>
#include <capnp/serialize.h>
#include "tools/cabana/streams/livestream.h"
#include "common/tests/native_test.h"
#include "tools/cabana/analysis/session.h"
#include "tools/cabana/analysis/workspace.h"
#include "tools/cabana/analysis/export.h"
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include "tools/cabana/ui/widgets/cameraview.h"
#include "openpilot/cereal/visionstream.h"
#include <sys/resource.h>
#include <sys/wait.h>
#include "msgq/visionipc/visionipc_server.h"
#include "msgq/visionipc/visionipc_client.h"
#include "tools/cabana/ui/chart/chartswidget.h"
#include "tools/cabana/ui/chart/chart.h"
#include "tools/cabana/ui/panel.h"

using J = json11::Json;

class TestStream : public DummyStream {
public:
  void append(double seconds, uint8_t value) {
    capnp::MallocMessageBuilder builder;
    auto message = builder.initRoot<cereal::CanData>();
    message.setSrc(0); message.setAddress(0x123);
    message.setDat(kj::ArrayPtr<const capnp::byte>(&value, 1));
    const auto *event = newEvent(seconds * 1e9, message.asReader());
    insertEvents({event}, {{{0, 0x123}, {event}}});
  }
};

class TestLiveStream : public LiveStream {
public:
  std::string routeName() const override { return "Synthetic cereal"; }
  void streamThread() override {
    for (int i = 0; i < 30 && !exit_; ++i) {
      capnp::MallocMessageBuilder builder;
      auto event = builder.initRoot<cereal::Event>();
      event.setLogMonoTime(1000000000ULL + i * 10000000ULL);
      event.setValid(true);
      event.initCarState().setVEgo(i);
      auto data = capnp::messageToFlatArray(builder);
      handleEvent(data.asPtr());
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }
};

void waitFor(cabana::AnalysisSession &session, const std::string &source) {
  for (int i = 0; i < 1000; ++i) {
    session.poll();
    if (session.samples(source)) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(false);
}

void test_docking() {
  ImGui::CreateContext();
  auto &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  io.IniFilename = nullptr;
  io.DisplaySize = ImVec2(1000, 700);
  unsigned char *pixels; int width, height;
  io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
  docking::Workspace docking;
  J tree = J::object{{"axis", "x"}, {"ratio", .3}, {"children", J::array{
    J::object{{"panes", J::array{"###Chart/a"}}}, J::object{{"panes", J::array{"###Chart/b", "###Chart/c"}}, {"selected", "###Chart/b"}}}}};
  std::map<std::string, J> layouts{{"one", tree}, {"two", tree}};
  std::string page = "one";
  bool added_plot = false;
  auto frame = [&] {
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("Host", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoDocking);
    docking.draw(page, {"one", "two"}, tree, [&](const auto &id) { return layouts[id]; },
                 [&](const auto &id, const auto &value) { layouts[id] = value; }, ImGui::GetContentRegionAvail(), false, 1);
    ImGui::End();
    for (const auto *name : {"A###Chart/a", "B###Chart/b", "C###Chart/c"}) {
      docking.dockWindow(name);
      setNextPanelClass(); beginPanel(name, nullptr); ImGui::TextUnformatted("Contents"); ImGui::End();
    }
    if (added_plot) {
      docking.dockWindow("D###Chart/d");
      setNextPanelClass(); beginPanel("D###Chart/d", nullptr); ImGui::End();
    }
    ImGui::Render();
  };
  for (int i = 0; i < 5; ++i) frame();
  auto *a = ImGui::FindWindowByName("###Chart/a");
  auto *b = ImGui::FindWindowByName("###Chart/b");
  auto *c = ImGui::FindWindowByName("###Chart/c");
  REQUIRE(a->DockNode && b->DockNode && b->DockNode == c->DockNode && a->DockNode != b->DockNode);
  REQUIRE(b->DockNode->SelectedTabId == b->TabId);
  io.AddMousePosEvent(a->Pos.x + 10, a->Pos.y + 10); frame();
  io.AddMouseButtonEvent(0, true); frame();
  io.AddMousePosEvent(420, 250); frame(); frame();
  io.AddMouseButtonEvent(0, false); frame(); frame();
  REQUIRE(!a->DockNode || !a->DockNode->IsDockSpace());
  REQUIRE(layouts["one"]["floating"].array_items().size() == 1);
  const auto floating = layouts["one"]["floating"][0];
  page = "two"; for (int i = 0; i < 4; ++i) frame();
  page = "one"; for (int i = 0; i < 4; ++i) frame();
  REQUIRE(layouts["one"]["floating"].array_items().size() == 1);
  REQUIRE(std::abs(layouts["one"]["floating"][0]["x"].number_value() - floating["x"].number_value()) < .02);
  io.DisplaySize = ImVec2(1400, 900); for (int i = 0; i < 4; ++i) frame();
  REQUIRE(b->DockNode == c->DockNode);
  docking.addWindow("###Chart/a");
  for (int i = 0; i < 5; ++i) frame();
  REQUIRE(a->DockNode && a->DockNode != b->DockNode);
  REQUIRE(a->DockNode->SelectedTabId == a->TabId);
  // Charts created by a browser/function action are discovered without an explicit addWindow call.
  added_plot = true;
  frame();  // Created after DockSpace: its first Begin must already be docked.
  auto *d = ImGui::FindWindowByName("###Chart/d");
  REQUIRE(d->DockNode && d->DockNode != a->DockNode && d->DockNode != b->DockNode);
  auto *root = d->DockNode;
  while (root->ParentNode) root = root->ParentNode;
  REQUIRE(root->IsDockSpace());
  ImGui::DestroyContext();
}

void test_tooltip_between_frames() {
  ImGui::CreateContext();
  ImPlot::CreateContext();
  auto &io = ImGui::GetIO();
  io.IniFilename = nullptr;
  io.DisplaySize = ImVec2(1000, 700);
  loadFonts();
  applyTheme(0);
  unsigned char *pixels; int width, height;
  io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
  TestStream stream;
  can = &stream;
  stream.fields["/speed"] = std::make_shared<const cabana::Samples>(cabana::Samples{{0, 0}, {1, 10}, {2, 20}});
  {
    cabana::AnalysisSession session(stream);
    ChartsWidget charts(session);
    auto chart = std::make_unique<ChartView>(std::make_pair(0.0, 2.0), &charts);
    auto connection = stream.timeRangeChanged.connect([&](const auto &range) {
      chart->updatePlot(stream.currentSec(), range->first, range->second);
    });
    chart->addSource("/speed");
    for (int i = 0; i < 2; ++i) {
      ImGui::NewFrame();
      ImGui::SetNextWindowSize(ImVec2(800, 600));
      ImGui::Begin(chart->windowName().c_str());
      chart->draw(ImGui::GetContentRegionAvail());
      chart->showTip(1);
      ImGui::End();
      ImGui::Render();
    }
    chart->hideTip();
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(900, 0));
    ImGui::SetNextWindowSize(ImVec2(80, 80));
    ImGui::Begin("Another pane");
    chart->showTip(1);
    REQUIRE(chart->signals()[0].track_pt.x == 1);
    ImGui::End();
    ImGui::Render();
    REQUIRE(GImGui->CurrentWindow == nullptr);
    // Stream notifications are drained before NewFrame, with a visible tooltip.
    stream.setTimeRange(std::make_pair(0.0, 3.0));
    REQUIRE(chart->signals()[0].track_pt.x == 1);
  }
  can = nullptr;
  ImPlot::DestroyContext();
  ImGui::DestroyContext();
}

void test_unavailable_camera() {
  const std::string name = "cabana-absent-test-" + std::to_string(getpid());
  const auto path = get_ipc_path(name);
  const int listener = ipc_bind(path.c_str());
  REQUIRE(listener >= 0);
  std::atomic<bool> stop = false;
  std::atomic<int> discoveries = 0, unsupported = 0;
  std::thread server([&]() {
    while (!stop) {
      pollfd pending{listener, POLLIN, 0};
      if (poll(&pending, 1, 20) <= 0) continue;
      int fd = accept(listener, nullptr, nullptr);
      if (fd < 0) continue;
      VisionStreamType request;
      if (ipc_sendrecv_with_fds(false, fd, &request, sizeof(request), nullptr, 0, nullptr) == sizeof(request)) {
        if (request == VISION_STREAM_LIST) {
          VisionStreamType available = VISION_STREAM_NARROW_ROAD;
          ipc_sendrecv_with_fds(true, fd, &available, sizeof(available), nullptr, 0, nullptr);
          ++discoveries;
        } else {
          ++unsupported;
        }
      }
      close(fd);
    }
  });
  {
    CameraWidget camera(name, VISION_STREAM_WIDE_ROAD);
    camera.setVisible(true);
    for (int i = 0; i < 100 && discoveries < 3; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    camera.setVisible(false);
  }
  stop = true;
  server.join();
  close(listener);
  unlink(path.c_str());
  REQUIRE(discoveries >= 3);
  REQUIRE(unsupported == 0);
}

void test_camera_fd_budget() {
  const pid_t child = fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_max < 512) _exit(2);
    limit.rlim_cur = 256;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(3);
    if (!utils::ensureCameraFileDescriptorLimit()) _exit(6);
    // Simulate the files/sockets already held by the UI, route readers, and decoders.
    for (int i = 0; i < 64; ++i) if (open("/dev/null", O_RDONLY) < 0) _exit(4);
    const std::string name = "cabana-fd-test-" + std::to_string(getpid());
    {
      VisionIpcServer server(name);
      for (auto type : {VISION_STREAM_NARROW_ROAD, VISION_STREAM_WIDE_ROAD, VISION_STREAM_CABIN})
        server.create_buffers_with_sizes(type, 40, 32, 32, 1536, 32, 1024);
      server.start_listener();
      VisionIpcClient road(name, VISION_STREAM_NARROW_ROAD, false);
      VisionIpcClient wide(name, VISION_STREAM_WIDE_ROAD, false);
      VisionIpcClient cabin(name, VISION_STREAM_CABIN, false);
      if (!road.connect() || !wide.connect() || !cabin.connect()) _exit(5);
    }
    _exit(0);
  }
  int status = 0;
  REQUIRE(waitpid(child, &status, 0) == child);
  REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void test_workspace_ui() {
  test_camera_fd_budget();
  test_unavailable_camera();
  test_docking();
  test_tooltip_between_frames();
  const auto csv_path = std::filesystem::temp_directory_path() / ("cabana-export-" + std::to_string(getpid()) + ".csv");
  cabana::exportVisibleCsv(csv_path.string(), {{"speed, \"CAN\"", {{0, 1}, {1, 2}, {2, 3}, {3, 4}}}}, 1, 2);
  std::ifstream csv_file(csv_path);
  const std::string csv{std::istreambuf_iterator<char>(csv_file), {}};
  csv_file.close(); std::filesystem::remove(csv_path);
  REQUIRE(csv == "time,series,value\n1,\"speed, \"\"CAN\"\"\",2\n2,\"speed, \"\"CAN\"\"\",3\n");
  TestStream stream;
  can = &stream;
  dbc()->open(SOURCE_ALL, "", "BO_ 291 Test: 1 XXX\n SG_ SPEED : 0|8@1+ (1,0) [0|255] \"m/s\" XXX\n");
  stream.append(1, 12); stream.append(2, 24);
  stream.fields["/carState/vEgo"] = std::make_shared<const cabana::Samples>(cabana::Samples{{1, 10}, {2, 20}});
  cabana::AnalysisSession session(stream);
  auto can_samples = session.samples("can/0:123|SPEED");
  REQUIRE(can_samples && can_samples->size() == 2 && can_samples->back().y == 24);
  REQUIRE(session.samples("can/0:123|SPEED") == can_samples);
  REQUIRE(session.display("can/0:123|SPEED", {}) == session.display("can/0:123|SPEED", {}));
  REQUIRE(session.transformed("can/0:123|SPEED", {.scale = 2}) == session.transformed("can/0:123|SPEED", {.scale = 2}));
  ChartsWidget charts(session);
  REQUIRE(cabana::validateWorkspace(cabana::defaultWorkspace()).empty());
  REQUIRE(charts.restoreWorkspace(cabana::defaultWorkspace()));
  REQUIRE(charts.widgetVisible("###MessagesPanel"));
  REQUIRE(charts.widgetVisible("###VideoPanel"));
  REQUIRE(charts.workspace()["pages"][0]["name"] == J("CAN"));
  const auto default_document = charts.workspace();
  can->setTimeRange(std::make_pair(1.2, 1.8));
  const auto global_range = can->timeRange();
  int range_changes = 0;
  auto range_connection = can->timeRangeChanged.connect([&](const auto &) { ++range_changes; });
  REQUIRE(charts.restoreWorkspace(cabana::blankWorkspace(), false));
  REQUIRE(can->timeRange() == global_range);
  REQUIRE(range_changes == 0);
  REQUIRE(charts.chartCount() == 0);
  REQUIRE(charts.widgetVisible("###ChartsWindow"));
  REQUIRE(charts.workspace()["pages"][0]["widgets"].array_items().size() == 1);
  REQUIRE(charts.pageLayout(charts.activePageId()) == cabana::browserPageLayout());
  charts.setWidgetVisible("###WideCameraPanel", true);
  charts.setWidgetVisible("###CabinCameraPanel", true);
  charts.addPlot();
  const auto custom_document = charts.workspace();
  REQUIRE(cabana::validateWorkspace(custom_document).empty());
  REQUIRE(charts.restoreWorkspace(default_document, false));
  REQUIRE(!charts.widgetVisible("###WideCameraPanel"));
  REQUIRE(charts.widgetVisible("###MessagesPanel"));
  REQUIRE(charts.restoreWorkspace(custom_document, false));
  REQUIRE(charts.widgetVisible("###WideCameraPanel"));
  REQUIRE(charts.widgetVisible("###CabinCameraPanel"));
  REQUIRE(charts.chartCount() == 1);
  REQUIRE(can->timeRange() == global_range);
  charts.setWidgetVisible("###WideCameraPanel", false);
  REQUIRE(charts.restoreWorkspace(charts.workspace(), false));
  REQUIRE(!charts.widgetVisible("###WideCameraPanel"));
  REQUIRE(range_changes == 0);
  range_connection.disconnect();
  const auto directory = std::filesystem::path(__FILE__).parent_path().parent_path() / "layouts";
  int count = 0;
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    if (entry.path().extension() != ".json") continue;
    std::ifstream file(entry.path());
    std::string error;
    auto document = J::parse(std::string(std::istreambuf_iterator<char>(file), {}), error);
    REQUIRE(error.empty());
    REQUIRE(charts.restoreWorkspace(document));
    auto saved = charts.workspace();
    std::map<std::string, J> expected_equations, actual_equations;
    for (const auto &e : saved["equations"].array_items()) actual_equations[e["id"].string_value()] = e;
    for (const auto &e : document["equations"].array_items()) expected_equations[e["id"].string_value()] = e;
    REQUIRE(actual_equations == expected_equations);
    REQUIRE(saved["pages"].array_items().size() == document["pages"].array_items().size());
    for (int i = 0; i < document["pages"].array_items().size(); ++i) {
      const auto &expected = document["pages"][i], &actual = saved["pages"][i];
      REQUIRE(expected["id"] == actual["id"] && expected["name"] == actual["name"] && expected["dock"] == actual["dock"]);
      REQUIRE(expected["panes"].array_items().size() == actual["panes"].array_items().size());
      for (int c = 0; c < expected["panes"].array_items().size(); ++c) {
        const auto &pane = expected["panes"][c], &copy = actual["panes"][c];
        for (const auto *key : {"id", "title", "range", "style", "y_lower", "y_upper"}) REQUIRE(pane[key] == copy[key]);
        REQUIRE(pane["curves"].array_items().size() == copy["curves"].array_items().size());
        for (int n = 0; n < pane["curves"].array_items().size(); ++n) {
          for (const auto *key : {"alias", "color", "visible", "transform"}) REQUIRE(pane["curves"][n][key] == copy["curves"][n][key]);
          REQUIRE(pane["curves"][n]["source"]["path"] == copy["curves"][n]["source"]["path"]);
        }
      }
    }
    REQUIRE(charts.restoreWorkspace(saved));
    REQUIRE(charts.workspace() == saved);
    ++count;
  }
  REQUIRE(count == 14);
  auto metadata = cabana::describeField("/carState/gearShifter");
  REQUIRE(!metadata.enumerants.empty());
  REQUIRE(cabana::describeField("/gpsLocationExternalDEPRECATED/flags").deprecated);
  const auto before = charts.workspace();
  REQUIRE(!charts.restoreWorkspace(J::object{{"cabana_workspace", 99}}));
  REQUIRE(charts.workspace() == before);
  auto invalid = before.object_items();
  auto pages = before["pages"].array_items();
  auto bad_page = pages[0].object_items();
  bad_page["dock"] = J::object{{"axis", "z"}, {"ratio", 2}, {"children", J::array{J::object{}, J::object{}}}};
  pages[0] = bad_page; invalid["pages"] = pages;
  REQUIRE(!charts.restoreWorkspace(invalid));
  REQUIRE(charts.workspace() == before);
  std::string parse_error;
  auto legacy = cabana::migrateWorkspace(J::parse(R"({"columns":2,"tabs":[[{"signals":[{"message":"0:123","signal":"SPEED","visible":false}]}]]})", parse_error));
  REQUIRE(cabana::validateWorkspace(legacy).empty());
  REQUIRE(legacy["pages"][0]["panes"][0]["curves"][0]["source"]["kind"] == J("can"));
  REQUIRE(!legacy["pages"][0]["panes"][0]["curves"][0]["visible"].bool_value());
  charts.removeAll();
  charts.showChart({0, 0x123}, dbc()->msg({0, 0x123})->sig("SPEED"), true, false);
  const auto bindings = charts.workspace();
  REQUIRE(cabana::validateWorkspace(bindings).empty());
  dbc()->closeAll();
  REQUIRE(charts.chartCount() == 1);
  REQUIRE(charts.workspace() == bindings);
  REQUIRE(!session.samples("can/0:123|SPEED"));
  dbc()->open(SOURCE_ALL, "", "BO_ 291 Test: 1 XXX\n SG_ SPEED : 0|8@1+ (2,0) [0|510] \"m/s\" XXX\n");
  REQUIRE(session.samples("can/0:123|SPEED")->back().y == 48);
  REQUIRE(charts.workspace() == bindings);
  session.setEquations({{"stable-id", {"Display name", "/carState/vEgo", "", "return value + v1", {"can/0:123|SPEED"}}}});
  waitFor(session, "equation/stable-id");
  REQUIRE(session.samples("equation/stable-id")->back().y == 68);
  charts.removeAll();
  REQUIRE(session.samples("equation/stable-id")->back().y == 68);
  stream.fields["/other"] = std::make_shared<const cabana::Samples>(cabana::Samples{{0, 1}, {10, 3}});
  session.setEquations({{"late", {"Late input", "/carState/vEgo", "", "return value + v1", {"/other"}}}});
  waitFor(session, "equation/late");
  auto old_result = session.samples("equation/late");
  REQUIRE(old_result->back().y == 21);
  stream.fields["/other"] = std::make_shared<const cabana::Samples>(cabana::Samples{{0, 1}, {1.8, 10}, {10, 3}});
  stream.fieldsChanged();
  for (int i = 0; i < 1000; ++i) {
    session.poll();
    if (session.samples("equation/late")->back().y == 30) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(session.samples("equation/late")->back().y == 30);
  REQUIRE(old_result->back().y == 21);
  auto large = std::make_shared<cabana::Samples>();
  for (int i = 0; i < 20000; ++i) large->emplace_back(i * .01, i);
  stream.fields["/large"] = large;
  session.setEquations({{"stale", {"Old", "/large", "", "return value + 1", {}}}});
  session.poll();
  session.setEquations({{"stale", {"Renamed", "/carState/vEgo", "", "return value + 100", {}}}});
  waitFor(session, "equation/stale");
  REQUIRE(session.samples("equation/stale")->size() == 2);
  REQUIRE(session.samples("equation/stale")->back().y == 120);
  REQUIRE(session.displayName("equation/stale") == "Renamed");
  session.setEquations({{"a", {"A", "equation/b", "", "return value", {}}},
                        {"b", {"B", "equation/a", "", "return value", {}}},
                        {"missing", {"Missing", "/absent", "", "return value", {}}}});
  for (int i = 0; i < 1000 && session.diagnostics().empty(); ++i) {
    session.poll();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(session.diagnostics().at("a") == "Dependency cycle");
  REQUIRE(session.diagnostics().at("missing").find("Waiting for") == 0);
  {
    TestLiveStream live;
    can = &live;
    live.start();
    for (int i = 0; i < 1000; ++i) {
      utils::drainMainThreadQueue();
      auto it = live.fields.find("/carState/vEgo");
      if (it != live.fields.end() && it->second->size() == 30) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    REQUIRE(live.fields.at("/carState/vEgo")->size() == 30);
    REQUIRE(live.fields.at("/carState/vEgo")->back().y == 29);
    REQUIRE(live.fields.count("/carState/__valid") == 1);
    REQUIRE(live.fields.count("/carState/__logMonoTime") == 1);
    REQUIRE(live.fields.count("/carState/__logMonoTimeSeconds") == 1);
    live.stop();
    can = &stream;
  }
}

int main(int argc, char **argv) {
  if (argc > 1 && std::string(argv[1]) == "--camera-fd-budget") return run_native_test(test_camera_fd_budget);
  return run_native_test(test_workspace_ui);
}
