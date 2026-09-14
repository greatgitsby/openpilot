#pragma once
#include <string>
#include "tools/cabana/analysis/fields.h"
namespace cabana {
// Samples are already transformed and expressed in display seconds by the caller.
void exportVisibleCsv(const std::string &path, const Fields &series, double first, double last);
}
