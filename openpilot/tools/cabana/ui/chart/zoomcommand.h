#pragma once

#include "tools/cabana/commands.h"
#include "tools/cabana/core/source.h"

// zooms the source that was current when created; a no-op once that source is gone
class ZoomCommand : public UndoCommand {
public:
  ZoomCommand(std::pair<double, double> range, std::optional<std::pair<double, double>> previous = can->timeRange())
      : prev_range(previous), range(range), source_(can), alive_(can->lifetime()) {}
  void undo() override { if (!alive_.expired()) source_->setTimeRange(prev_range); }
  void redo() override { if (!alive_.expired()) source_->setTimeRange(range); }
  std::optional<std::pair<double, double>> prev_range, range;

private:
  AbstractStream *source_;
  std::weak_ptr<bool> alive_;
};
