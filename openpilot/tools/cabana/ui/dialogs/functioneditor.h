#pragma once

#include <functional>
#include "tools/cabana/analysis/equations.h"
#include "tools/cabana/ui/util.h"

class FunctionEditor {
public:
  void open(const cabana::Equation &equation, std::function<void(cabana::Equation)> save) {
    draft_ = equation; save_ = std::move(save); open_ = true; popup_.reset();
  }
  void draw();
private:
  bool open_ = false;
  PopupOwner popup_;
  cabana::Equation draft_;
  std::function<void(cabana::Equation)> save_;
};
