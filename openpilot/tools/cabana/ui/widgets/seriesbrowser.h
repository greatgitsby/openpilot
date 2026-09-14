#pragma once
#include <functional>
#include "imgui_internal.h"
#include <unordered_set>
#include "tools/cabana/analysis/session.h"
#include "tools/cabana/ui/chart/signaltree.h"

// Reusable hierarchical source picker. A drop adds a curve; dock tabs move panes.
class SeriesBrowser {
public:
  void draw(cabana::AnalysisSession &session, const std::function<void(const std::string &, bool)> &plot);
private:
  chart::SignalTree tree_;
  std::vector<std::string> sources_;
  std::unordered_set<std::string> expanded_{"equation"};
  std::string filter_;
  uint64_t revision_ = 0;
  bool show_deprecated_ = false;
};
std::string droppedSeries(const ImRect &area);
