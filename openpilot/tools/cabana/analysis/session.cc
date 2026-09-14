#include "tools/cabana/analysis/session.h"
#include <chrono>
#include <functional>
#include "json11/json11.hpp"
#include "tools/cabana/dbc/dbcmanager.h"

namespace cabana {
AnalysisSession::AnalysisSession(AbstractStream &stream) : stream_(stream) {
  connections_.push_back(stream.eventsMerged.connect([this](const auto &) { invalidate(); }));
  connections_.push_back(stream.fieldsChanged.connect([this]() { if (cancel_) *cancel_ = true; ++revision_; }));
  connections_.push_back(dbc()->fileChanged.connect([this]() { invalidate(); }));
  connections_.push_back(dbc()->signalUpdated.connect([this](auto) { invalidate(); }));
  connections_.push_back(dbc()->signalAdded.connect([this](auto, auto) { invalidate(); }));
  connections_.push_back(dbc()->signalRemoved.connect([this](auto) { invalidate(); }));
  connections_.push_back(dbc()->msgRemoved.connect([this](auto) { invalidate(); }));
}
AnalysisSession::~AnalysisSession() { if (cancel_) *cancel_ = true; if (job_.valid()) job_.wait(); }
void AnalysisSession::invalidate() { if (cancel_) *cancel_ = true; decoded_.clear(); ++revision_; }

std::shared_ptr<const Samples> AnalysisSession::samples(const std::string &source) {
  if (source.rfind("equation/", 0) == 0) {
    auto it = derived_.find(source);
    return it == derived_.end() ? nullptr : it->second;
  }
  if (source.rfind("can/", 0) != 0) {
    auto it = stream_.fields.find(source);
    return it == stream_.fields.end() ? nullptr : it->second;
  }
  if (auto it = decoded_.find(source); it != decoded_.end()) return it->second;
  const auto separator = source.find('|', 4);
  auto id = MessageId::parse(source.substr(4, separator - 4));
  if (!id || separator == std::string::npos) return nullptr;
  auto *message = dbc()->msg(*id);
  const auto *signal = message ? message->sig(source.substr(separator + 1)) : nullptr;
  if (!signal) return nullptr;
  auto result = std::make_shared<Samples>();
  if (auto it = stream_.eventsMap().find(*id); it != stream_.eventsMap().end()) {
    result->reserve(it->second.size());
    for (const auto *event : it->second) {
      double value;
      if (signal->getValue(event->dat, event->size, &value)) result->emplace_back(event->mono_time * 1e-9, value);
    }
  }
  decoded_[source] = result;
  return result;
}

void AnalysisSession::setEquations(const std::map<std::string, Equation> &definitions) {
  if (cancel_) *cancel_ = true;
  equations_ = definitions;
  derived_.clear(); diagnostics_.clear(); ++revision_;
}
std::vector<std::string> AnalysisSession::sources() const {
  std::vector<std::string> names;
  for (const auto &[id, _] : stream_.eventsMap()) if (auto *message = dbc()->msg(id)) {
    for (const auto *signal : message->getSignals()) names.push_back("can/" + id.toString() + "|" + signal->name);
  }
  for (const auto &[name, _] : stream_.fields) names.push_back(name);
  for (const auto &[id, _] : equations_) names.push_back("equation/" + id);
  return names;
}
void AnalysisSession::poll() {
  if (job_.valid()) {
    if (job_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
    auto result = job_.get();
    if (result.revision == revision_) {
      derived_ = std::move(result.outputs);
      diagnostics_ = std::move(result.diagnostics);
      evaluated_revision_ = revision_;
    }
  }
  if (equations_.empty() || evaluated_revision_ == revision_) return;
  FieldsSnapshot inputs = stream_.fields;
  for (const auto &[_, definition] : equations_) {
    if (auto data = samples(definition.source)) inputs[definition.source] = data;
    for (const auto &input : definition.additional) if (auto data = samples(input)) inputs[input] = data;
  }
  cancel_ = std::make_shared<std::atomic<bool>>(false);
  job_ = std::async(std::launch::async, [cancelled = cancel_, inputs = std::move(inputs), definitions = equations_, revision = revision_]() mutable {
    Evaluation result{revision, {}, {}};
    std::map<std::string, int> states;
    std::function<bool(const std::string &)> evaluate = [&](const std::string &id) {
      if (states[id] == 2) return result.diagnostics.count(id) == 0;
      if (states[id] == 1) { result.diagnostics[id] = "Dependency cycle"; return false; }
      states[id] = 1;
      auto it = definitions.find(id);
      if (it == definitions.end()) { result.diagnostics[id] = "Missing equation"; states[id] = 2; return false; }
      const auto &equation = it->second;
      std::vector<std::string> dependencies = equation.additional;
      dependencies.push_back(equation.source);
      bool ready = true;
      for (const auto &source : dependencies) {
        if (source.rfind("equation/", 0) == 0 && !evaluate(source.substr(9))) {
          if (!result.diagnostics.count(id)) result.diagnostics[id] = "Dependency error: " + source;
          ready = false;
        }
      }
      if (ready) try {
        auto output = std::make_shared<const Samples>(evaluateEquation(equation, inputs, cancelled.get()));
        inputs["equation/" + id] = output;
        result.outputs["equation/" + id] = output;
      } catch (const std::exception &error) { result.diagnostics[id] = error.what(); }
      states[id] = 2;
      return result.diagnostics.count(id) == 0;
    };
    for (const auto &[id, _] : definitions) evaluate(id);
    return result;
  });
}
}

namespace cabana {
std::shared_ptr<const Samples> AnalysisSession::transformed(const std::string &source, const TransformSettings &s) {
  auto input = samples(source);
  if (!input || (s.type == Transform::None && s.scale == 1 && s.offset == 0 && s.time_offset == 0)) return input;
  const std::string key = json11::Json(json11::Json::array{source, (int)s.type, s.scale, s.offset, s.time_offset, s.derivative_divisor, s.window}).dump();
  auto &cached = transforms_[key];
  if (cached.input != input) {
    cached.input = input;
    cached.output = std::make_shared<const Samples>(transformSamples(*input, s));
  }
  return cached.output;
}
}

namespace cabana {
std::string AnalysisSession::displayName(const std::string &source) const {
  if (source.rfind("equation/", 0) == 0) {
    auto it = equations_.find(source.substr(9));
    if (it != equations_.end()) return it->second.name;
  }
  return source;
}
}

namespace cabana {
std::shared_ptr<const DisplaySamples> AnalysisSession::display(const std::string &source, const TransformSettings &s) {
  auto input = transformed(source, s);
  const std::string key = json11::Json(json11::Json::array{source, (int)s.type, s.scale, s.offset, s.time_offset, s.derivative_divisor, s.window}).dump();
  auto &cached = displays_[key];
  const double origin = stream_.beginMonoTime() * 1e-9;
  if (!cached || cached->source != input || cached->origin != origin) {
    auto data = std::make_shared<DisplaySamples>();
    data->source = input;
    data->origin = origin;
    if (input) {
      data->values.reserve(input->size());
      data->steps.reserve(input->size() * 2);
      for (const auto &point : *input) {
        const double time = point.x - origin;
        data->values.emplace_back(time, point.y);
        if (!data->steps.empty()) data->steps.emplace_back(time, data->steps.back().y);
        data->steps.emplace_back(time, point.y);
      }
      data->bounds.build(data->values.size(), [&data](int i) { return data->values[i].y; });
    }
    cached = data;
  }
  return cached;
}
}
