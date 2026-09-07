#include "tools/cabana/commands.h"

#include <algorithm>

// UndoStack

void UndoStack::push(UndoCommand *cmd) {
  if (clean_index_ > index_) clean_index_ = isClean() ? index_ : -1;
  commands_.resize(index_);  // drop any redoable commands
  commands_.emplace_back(cmd);
  cmd->redo();
  setIndex(index_ + 1);
}

void UndoStack::undo() {
  if (!canUndo()) return;
  commands_[index_ - 1]->undo();
  setIndex(index_ - 1);
}

void UndoStack::redo() {
  if (!canRedo()) return;
  commands_[index_]->redo();
  setIndex(index_ + 1);
}

void UndoStack::clear() {
  bool was_clean = isClean();
  commands_.clear();
  index_ = clean_index_ = 0;
  indexChanged();
  if (!was_clean) cleanChanged(true);
}

bool UndoStack::isClean() const {
  if (clean_index_ < 0) return false;
  for (int i = std::min(clean_index_, index_); i < std::max(clean_index_, index_); ++i) {
    if (commands_[i]->changes_document) return false;
  }
  return true;
}

void UndoStack::setClean() {
  if (!isClean()) {
    clean_index_ = index_;
    cleanChanged(true);
  }
}

void UndoStack::setIndex(int index) {
  bool was_clean = isClean();
  index_ = index;
  indexChanged();
  if (isClean() != was_clean) cleanChanged(isClean());
}

UndoStack *UndoStack::instance() {
  static UndoStack undo_stack;
  return &undo_stack;
}

