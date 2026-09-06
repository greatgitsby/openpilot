#pragma once
#include <set>
#include <unordered_map>
#include "tools/cabana/analysis/layout.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/ui/widgets/cameraview.h"
#include "tools/cabana/ui/widgets/analysiscamera.h"
#include "tools/cabana/ui/widgets/videowidget.h"

class AnalysisWorkspace {
public:
  AnalysisWorkspace();
  ~AnalysisWorkspace();
  void draw();
  void menu();
  void shortcut(int key, bool shift);
  void load(const std::string &path);
  void restore(const std::string &json);
  void save(const std::string &path);
  std::string state() const;
  bool visible = false;
private:
  using Pane = cabana::analysis::Pane;
  void toolbar();
  void record(const std::string &label);
  bool button(const char *label);
  bool menuItem(const char *label);
  bool textInput(const char *label, std::string *value);
  json11::Json::object test_items_, test_plots_, test_texts_;
  void browser();
  void pane(Pane &p, ImVec2 size, const std::string &id);
  void plot(Pane &p, ImVec2 size);
  void map(ImVec2 size);
  std::future<json11::Json> map_request_;
  std::vector<std::vector<cabana::analysis::Sample>> map_roads_;
  std::string map_error_, map_key_;
  bool map_streets_ = false, map_follow_ = false;
  void logs(ImVec2 size);
  void media(Pane &p, ImVec2 size, const std::string &id);
  void editor();
  void evaluate(bool apply);
  void pollEvaluation();
  void refreshFormulas();
  json11::Json formulaInputs(const std::vector<cabana::analysis::Formula> &formulas) const;
  void refreshCan();
  void checkpoint();
  void undo(int direction);
  void addSelected(Pane &p);
  const cabana::analysis::Channel *channel(const std::string &name) const;
  double origin() const { return can->beginMonoTime() * 1e-9; }
  cabana::analysis::Layout layout_;
  std::vector<std::string> history_;
  int history_pos_ = -1;
  std::string filter_, selected_, path_, error_, log_filter_, source_filter_;
  std::set<std::string> selection_, expanded_paths_, active_cameras_;
  bool tree_browser_ = true, select_tab_ = true, layout_editor_ = false;
  std::string layout_source_;
  std::map<std::string, cabana::analysis::Channel> can_channels_, custom_channels_;
  std::unordered_map<std::string, std::unique_ptr<StreamCameraView>> cameras_;
  std::unordered_map<std::string, std::unique_ptr<AnalysisCamera>> file_cameras_;
  GlTexture thumbnail_;
  struct PlotCache {
    uint64_t revision = 0;
    size_t count = 0;
    double last_time = -1, last_value = 0;
    std::vector<cabana::analysis::Sample> points;
  };
  std::map<std::string, PlotCache> plot_cache_;
  uint64_t data_revision_ = 0, can_revision_ = 0;
  bool focus_search_ = false;
  bool dbc_dirty_ = true, deprecated_ = false, follow_ = false, loop_ = false, formula_open_ = false;
  bool range_initialized_ = false, fps_ = false;
  double x_min_ = 0, x_max_ = 10, step_ = 0.1;
  int log_level_ = 0, log_time_ = 0;
  unsigned log_levels_ = 0x3f;
  std::set<std::string> log_sources_;
  cabana::analysis::Formula formula_;
  std::string extra_sources_;
  std::vector<cabana::analysis::Sample> preview_;
  std::future<json11::Json> evaluation_;
  cabana::analysis::Formula evaluating_formula_;
  bool apply_evaluation_ = false, batch_evaluation_ = false;
  uint64_t formulas_revision_ = 0;
  std::string formula_signature_, autosave_snapshot_;
  double next_formula_refresh_ = 0, next_autosave_ = 0;
  std::map<std::string, std::string> formula_errors_;
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
  Connections connections_;
};
