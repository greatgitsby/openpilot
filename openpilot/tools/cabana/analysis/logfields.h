#pragma once
#include <atomic>
#include "tools/cabana/analysis/fields.h"
#include "tools/replay/logreader.h"

namespace cabana {
inline Fields extractLogFields(const LogReader &log, const std::atomic<bool> &stopping) {
  Fields batch;
  FieldExtractor extractor(batch);
  for (const auto &event : log.events) {
    if (stopping.load(std::memory_order_relaxed)) return {};
    if (event.eidx_segnum != -1 || event.which == cereal::Event::Which::CAN || event.which == cereal::Event::Which::SENDCAN) continue;
    capnp::FlatArrayMessageReader reader(event.data);
    extractor.extract(reader.getRoot<cereal::Event>());
  }
  return batch;
}
}
