#include <thread>

#include "common/tests/native_test.h"
#include "tools/cabana/commands.h"
#include "tools/cabana/core/source.h"
#include "tools/cabana/streams/abstractstream.h"

namespace {
class TestSource : public DummyStream {
public:
  using AbstractStream::postToMainThread;
  using AbstractStream::updateEvent;
  using AbstractStream::updateLastMessages;
};
}

void test_source_isolation() {
  TestSource first, second;
  first.source_id = "first";
  second.source_id = "second";
  registerSource(&first);
  registerSource(&second);
  registerSource(&first);
  REQUIRE(sourceById("first") == &first);
  REQUIRE(sourceById("second") == &second);
  REQUIRE(sourceById("missing") == nullptr);

  SourceScope outer(&first);
  REQUIRE(can == &first);
  REQUIRE(dbc() == first.database());
  REQUIRE(UndoStack::instance() == first.undoStack());
  {
    SourceScope inner(&second);
    REQUIRE(can == &second);
    REQUIRE(dbc() == second.database());
    REQUIRE(UndoStack::instance() == second.undoStack());
  }
  REQUIRE(can == &first);

  const MessageId id{0, 100};
  REQUIRE(first.database()->open(SOURCE_ALL, "first", "BO_ 100 First: 8 ECU\n"));
  REQUIRE(second.database()->open(SOURCE_ALL, "second", "BO_ 100 Second: 8 ECU\n"));
  bool delivered = false;
  auto connection = second.database()->msgUpdated.connect([&](MessageId changed) {
    REQUIRE(changed == id);
    REQUIRE(can == &second);
    REQUIRE(dbc() == second.database());
    delivered = true;
  });
  // A direct call to an inactive source binds its notifications to that source.
  second.database()->updateMsg(id, "Other", 8, "ECU", "");
  REQUIRE(delivered);
  REQUIRE(can == &first);
  REQUIRE(first.database()->msg(id)->name == "First");
  REQUIRE(second.database()->msg(id)->name == "Other");

  first.undoStack()->push(new EditMsgCommand(id, "First edited", 8, "ECU", ""));
  {
    SourceScope inner(&second);
    second.undoStack()->push(new EditMsgCommand(id, "Second edited", 8, "ECU", ""));
  }
  // Undo explicitly on an inactive source: only its database and stack change.
  second.undoStack()->undo();
  REQUIRE(second.database()->msg(id)->name == "Other");
  REQUIRE(first.database()->msg(id)->name == "First edited");
  REQUIRE(first.undoStack()->canUndo());
  REQUIRE(!second.undoStack()->canUndo());
  second.undoStack()->redo();
  REQUIRE(second.database()->msg(id)->name == "Second edited");
  first.undoStack()->undo();
  REQUIRE(first.database()->msg(id)->name == "First");

  delivered = false;
  std::thread worker([&]() {
    // Startup loaders may construct/destroy an unregistered source off-thread.
    { TestSource pending; }
    const uint8_t value = 42;
    second.updateEvent(id, 10, &value, 1);
    second.postToMainThread([&]() {
      REQUIRE(can == &second);
      REQUIRE(dbc() == second.database());
      second.updateLastMessages();
      delivered = true;
    });
  });
  worker.join();
  utils::drainMainThreadQueue();
  REQUIRE(delivered);
  REQUIRE(can == &first);
  REQUIRE(second.lastMessage(id).dat == std::vector<uint8_t>{42});
  REQUIRE(first.lastMessages().empty());

  auto old = std::make_unique<TestSource>();
  old->source_id = "replaceable";
  registerSource(old.get());
  bool stale_called = false;
  auto bound = bindSource(old.get(), [&]() { stale_called = true; });
  std::thread enqueue([&]() {
    old->postToMainThread([&]() { stale_called = true; });
  });
  enqueue.join();
  old.reset();
  REQUIRE(sourceById("replaceable") == nullptr);
  TestSource replacement;
  replacement.source_id = "replaceable";
  registerSource(&replacement);
  REQUIRE(sourceById("replaceable") == &replacement);
  bound();
  utils::drainMainThreadQueue();
  REQUIRE(!stale_called);
  REQUIRE(can == &first);

  unregisterSource(&first);
  unregisterSource(&second);
  unregisterSource(&replacement);
  REQUIRE(sourceById("first") == nullptr);
}
