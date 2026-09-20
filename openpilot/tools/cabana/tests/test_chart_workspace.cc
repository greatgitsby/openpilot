#include "common/tests/native_test.h"
#include "tools/cabana/ui/chart/layout.h"

using json11::Json;

void test_chart_workspaces() {
{
  const Json telemetry = Json::object{{"source", "source1"}, {"path", "/carState/vEgo"}};
  const Json comparison = Json::object{{"source", "source2"}, {"path", "/carState/vEgo"}};
  const Json can_signal = Json::object{{"source", "source2"}, {"message", "0:123"}, {"signal", "SPEED"}};
  Json::object document{{"cabana_layout", 4}, {"range", 10}, {"charts", Json::array{
    Json::object{{"id", "plot-42"}, {"title", "Compare speed"}, {"type", 0}, {"signals", Json::array{telemetry, comparison, can_signal}}},
    Json::object{{"id", "plot-43"}, {"type", 0}, {"signals", Json::array{}}}}}};
  auto layout = chart::parseLayout(Json(document).dump());
  REQUIRE(layout.has_value());
  REQUIRE(layout->tabs.size() == 1);
  REQUIRE(layout->tabs[0].size() == 2);
  const auto &plot = layout->tabs[0][0];
  REQUIRE(plot.widget_id == "plot-42");
  REQUIRE(plot.signals.size() == 3);
  REQUIRE(plot.signals[0].path == plot.signals[1].path);
  REQUIRE(plot.signals[0].source_id == "source1");
  REQUIRE(plot.signals[1].source_id == "source2");
  REQUIRE(plot.signals[2].name == "SPEED");
  REQUIRE(layout->tabs[0][1].signals.empty());

  auto charts = document["charts"].array_items();
  auto duplicate = charts[1].object_items();
  duplicate["id"] = "plot-42";
  charts[1] = duplicate;
  document["charts"] = charts;
  REQUIRE(!chart::parseLayout(Json(document).dump()));
  duplicate["id"] = "bad###window";
  charts[1] = duplicate;
  document["charts"] = charts;
  REQUIRE(!chart::parseLayout(Json(document).dump()));
}

// Blank arrangements and malformed source references.
{
  Json::object document{{"cabana_layout", 4}, {"range", 60}, {"charts", Json::array{}}};
  REQUIRE(chart::parseLayout(Json(document).dump()).has_value());
  for (const auto &bad_source : Json::array{Json(12), Json(true), Json::array{"source1"}}) {
    document["charts"] = Json::array{Json::object{{"id", "1"}, {"type", 0},
      {"signals", Json::array{Json::object{{"source", bad_source}, {"path", "/carState/vEgo"}}}}}};
    REQUIRE(!chart::parseLayout(Json(document).dump()));
  }
}

// Legacy chart tab descriptors remain importable.
{
  const Json chart = Json::object{{"type", 0}, {"signals", Json::array{Json::object{{"path", "/carState/vEgo"}}}}};
  const Json document = Json::object{{"cabana_layout", 3}, {"columns", 2}, {"range", 60},
    {"tabs", Json::array{Json::array{chart}, Json::array{chart}}}, {"active_tab", 1}};
  auto layout = chart::parseLayout(document.dump());
  REQUIRE(layout.has_value());
  REQUIRE(layout->tabs.size() == 2);
  REQUIRE(layout->tabs[0][0].signals[0].source_id.empty());
  REQUIRE(layout->tabs[1][0].widget_id.empty());
}

}
