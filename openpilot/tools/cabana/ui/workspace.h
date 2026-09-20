#pragma once

#include "tools/cabana/ui/chart/layout.h"

namespace cabana {
// A workspace wraps the existing chart format with the native frontend's panel layout.
inline bool validWorkspace(const json11::Json &doc) {
  if (doc["cabana_workspace"] != 1 || !doc["name"].is_string() || doc["name"].string_value().empty() ||
      !doc["ui"].is_string() || !chart::parseLayout(doc["charts"].dump())) return false;
  for (const char *panel : {"messages", "logs", "charts", "video", "details", "playback"}) {
    if (!doc["panels"][panel].is_bool()) return false;
  }
  return true;
}
}  // namespace cabana
