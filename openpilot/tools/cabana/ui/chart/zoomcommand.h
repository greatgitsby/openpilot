#pragma once

#include "tools/cabana/commands.h"
#include "tools/cabana/core/source.h"

class ZoomCommand : public UndoCommand {
public:
  ZoomCommand(std::pair<double, double> range) : ZoomCommand(range, can->timeRange()) {}
  ZoomCommand(std::pair<double, double> range, std::optional<std::pair<double, double>> previous)
      : prev_range(previous), range(range), source_id_(can ? can->source_id : ""), source_alive_(can ? can->lifetime() : std::weak_ptr<bool>{}) {}
  void undo() override { if (auto *source = source_alive_.expired() ? nullptr : sourceById(source_id_)) source->setTimeRange(prev_range); }
  void redo() override { if (auto *source = source_alive_.expired() ? nullptr : sourceById(source_id_)) source->setTimeRange(range); }
  std::optional<std::pair<double, double>> prev_range, range;
  std::string source_id_;
  std::weak_ptr<bool> source_alive_;
};
