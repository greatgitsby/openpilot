#pragma once
#include <string>
#include "json11/json11.hpp"

namespace cabana::analysis {
// Executes a helper with no shell; terminates its process group after the deadline.
json11::Json pythonTask(const std::string &script, const json11::Json &request, double timeout_seconds = 15);
}
