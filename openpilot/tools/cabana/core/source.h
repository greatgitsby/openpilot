#pragma once

#include <memory>
#include <string>
#include <vector>
#include <utility>

#include "tools/cabana/streams/abstractstream.h"

class AbstractStream;

// Main-thread compatibility bridge for legacy widgets. New data access should use
// the owning stream explicitly. Nested scopes restore the previous source.
class SourceScope {
public:
  explicit SourceScope(AbstractStream *stream);
  ~SourceScope();
  SourceScope(const SourceScope &) = delete;
  SourceScope &operator=(const SourceScope &) = delete;
private:
  AbstractStream *previous_;
  std::weak_ptr<bool> previous_alive_;
};

const std::vector<AbstractStream *> &sources();
AbstractStream *sourceById(const std::string &id);
void registerSource(AbstractStream *stream);
void unregisterSource(AbstractStream *stream);

// Bind settings/global notifications to the widget's source, dropping delivery
// after that source has been destroyed. Intended for main-thread callbacks.
template <typename Handler>
auto bindSource(AbstractStream *stream, Handler handler) {
  return [stream, alive = stream ? stream->lifetime() : std::weak_ptr<bool>{}, handler = std::move(handler)](auto &&...args) mutable {
    if (stream && alive.expired()) return;
    SourceScope scope(stream);
    handler(std::forward<decltype(args)>(args)...);
  };
}
