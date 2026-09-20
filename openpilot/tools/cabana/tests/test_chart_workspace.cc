#include "common/tests/native_test.h"
#include "tools/cabana/ui/chart/layout.h"
#include "tools/cabana/ui/workspace.h"

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

// Shared source IDs may collide with routes already open in the receiving app.
{
  const Json document = Json::object{
    {"cabana_workspace", 2}, {"name", "Comparison"}, {"ui", ""},
    {"sources", Json::array{Json::object{{"id", "source1"}, {"label", "Saved route"}, {"route", "route-b"},
      {"inspector", Json::object{{"active", "0:123"}, {"messages", Json::array{"0:123", "1:456"}}}}}}},
    {"widgets", Json::array{Json::object{{"kind", "inspector"}, {"source", "source1"}},
      Json::object{{"kind", "camera"}, {"id", "camera1"}, {"source", "source1"}, {"camera", 0}, {"crop", true}}}},
    {"timeline", Json::object{{"selected", "source1"}, {"linked_master", "source1"}, {"loop_source", "source1"},
      {"linked", Json::array{"source1"}}, {"positions", Json::object{{"source1", 12}}}, {"offsets", Json::object{{"source1", -3}}}}},
    {"charts", Json::object{{"cabana_layout", 4}, {"range", 60}, {"charts", Json::array{
      Json::object{{"id", "1"}, {"type", 0}, {"signals", Json::array{
        Json::object{{"source", "source1"}, {"path", "/carState/vEgo"}}}}}}}}}};
  REQUIRE(cabana::validWorkspace(document));
  const auto rebound = cabana::remapWorkspaceSource(document, "source1", "source3");
  REQUIRE(cabana::validWorkspace(rebound));
  REQUIRE(rebound["sources"][0]["id"] == "source3");
  REQUIRE(rebound["sources"][0]["route"] == "route-b");
  REQUIRE(rebound["sources"][0]["inspector"] == document["sources"][0]["inspector"]);
  REQUIRE(rebound["widgets"][0]["source"] == "source3");
  REQUIRE(rebound["widgets"][1]["crop"].bool_value());
  REQUIRE(rebound["widgets"][1]["id"] == "camera1");
  for (const char *key : {"selected", "linked_master", "loop_source"}) REQUIRE(rebound["timeline"][key] == "source3");
  REQUIRE(rebound["timeline"]["linked"][0] == "source3");
  REQUIRE(rebound["timeline"]["offsets"]["source3"] == -3);
  REQUIRE(rebound["timeline"]["positions"]["source3"] == 12);
  REQUIRE(rebound["timeline"]["positions"]["source1"].is_null());
  REQUIRE(rebound["charts"]["charts"][0]["signals"][0]["source"] == "source3");
  // Opening a saved slot that refers to an already open route merges identities.
  auto duplicate = document.object_items();
  auto duplicate_sources = document["sources"].array_items();
  duplicate_sources.push_back(Json::object{{"id", "source3"}, {"label", "Existing route"}, {"route", "route-b"}});
  duplicate["sources"] = duplicate_sources;
  auto timeline = document["timeline"].object_items();
  timeline["linked"] = Json::array{"source1", "source3"};
  timeline["positions"] = Json::object{{"source1", 12}, {"source3", 25}};
  duplicate["timeline"] = timeline;
  const auto merged = cabana::remapWorkspaceSource(duplicate, "source1", "source3");
  REQUIRE(cabana::validWorkspace(merged));
  REQUIRE(merged["sources"].array_items().size() == 1);
  REQUIRE(merged["sources"][0]["label"] == "Existing route");
  REQUIRE(merged["timeline"]["linked"].array_items().size() == 1);
  REQUIRE(merged["timeline"]["positions"]["source3"] == 25);
  REQUIRE(merged["widgets"][0]["source"] == "source3");
  REQUIRE(merged["charts"]["charts"][0]["signals"][0]["source"] == "source3");
  REQUIRE(cabana::remapWorkspaceSource(merged, "source3", "source3") == merged);
  auto bad = rebound.object_items();
  auto sources = rebound["sources"].array_items();
  auto source = sources[0].object_items();
  source["inspector"] = Json::object{{"active", ""}, {"messages", Json::array{42}}};
  sources[0] = source;
  bad["sources"] = sources;
  REQUIRE(!cabana::validWorkspace(bad));
}

}
