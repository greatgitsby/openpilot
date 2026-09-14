#pragma once
#include <string>
#include "json11/json11.hpp"

namespace cabana {
json11::Json browserPageLayout();
json11::Json blankWorkspace();
json11::Json defaultWorkspace();
// Validate before replacing a live document, so failed imports leave it intact.
json11::Json migrateWorkspace(const json11::Json &document);
std::string validateWorkspace(const json11::Json &document);
}
