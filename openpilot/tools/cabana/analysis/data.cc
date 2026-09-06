#include "tools/cabana/analysis/data.h"

#include <algorithm>
#include <cmath>
#include <iterator>
#include "json11/json11.hpp"

namespace cabana::analysis {
std::optional<double> Channel::at(double time) const {
  const auto &points = samples();
  auto it = std::upper_bound(points.begin(), points.end(), time, [](double t, const Sample &s) { return t < s.time; });
  return it == points.begin() ? std::nullopt : std::optional<double>(std::prev(it)->value);
}

void Data::visit(const std::string &path, capnp::DynamicValue::Reader value, double time, int depth) {
  if (depth > 32) return;
  using V = capnp::DynamicValue;
  std::optional<double> number;
  switch (value.getType()) {
    case V::BOOL: number = value.as<bool>(); break;
    case V::INT: number = value.as<int64_t>(); break;
    case V::UINT: number = value.as<uint64_t>(); break;
    case V::FLOAT: number = value.as<double>(); break;
    case V::ENUM: {
      auto e = value.as<capnp::DynamicEnum>();
      number = e.getRaw();
      KJ_IF_MAYBE(label, e.getEnumerant()) { channels[path].labels[e.getRaw()] = label->getProto().getName().cStr(); }
      break;
    }
    case V::STRUCT: {
      auto object = value.as<capnp::DynamicStruct>();
      for (auto field : object.getSchema().getFields()) {
        if (object.has(field)) visit(path + "/" + field.getProto().getName().cStr(), object.get(field), time, depth + 1);
      }
      break;
    }
    case V::LIST: {
      auto list = value.as<capnp::DynamicList>();
      for (unsigned i = 0; i < list.size(); ++i) visit(path + "/" + std::to_string(i), list[i], time, depth + 1);
      break;
    }
    default: break;
  }
  if (number && std::isfinite(*number)) channels[path].editSamples().push_back({time, *number});
}

void Data::append(cereal::Event::Reader event) {
  double time = event.getLogMonoTime() * 1e-9;
  first = revision ? std::min(first, time) : time;
  last = std::max(last, time);
  ++revision;
  auto object = capnp::toDynamic(event);
  KJ_IF_MAYBE(field, object.which()) {
    std::string service = field->getProto().getName().cStr();
    std::string root = "/" + service;
    channels[root + "/__logMonoTime"].editSamples().push_back({time, double(event.getLogMonoTime())});
    channels[root + "/__logMonoTimeSeconds"].editSamples().push_back({time, time});
    channels[root + "/__valid"].editSamples().push_back({time, double(event.getValid())});
    if (service != "can" && service != "sendcan") visit(root, object.get(*field), time);
    if (service == "sendcan") {
      for (auto frame : event.getSendcan()) {
        auto bytes = frame.getDat();
        if (bytes.size() <= 64) sent_frames.push_back({time, frame.getAddress(), frame.getSrc(), {bytes.begin(), bytes.end()}});
      }
    }
    if (service == "operatingSystemLog") {
      auto entry = event.getOperatingSystemLog();
      logs.push_back({time, entry.getTs() * 1e-9, std::clamp((int(entry.getPriority()) - 1) * 10, 10, 50),
                     entry.getTag().cStr(), entry.getMessage().cStr(), "pid=" + std::to_string(entry.getPid()) + " tid=" + std::to_string(entry.getTid())});
    } else if (service == "selfdriveState") {
      auto state = event.getSelfdriveState();
      std::string message = std::string(state.getAlertText1().cStr()) + " " + state.getAlertText2().cStr();
      if (message != " " && (logs.empty() || logs.back().message != message))
        logs.push_back({time, 0, 20 + int(state.getAlertStatus()) * 10, "Alert", message, state.getAlertType().cStr()});
    } else if (service == "logMessage" || service == "errorLogMessage") {
      std::string message = object.get(*field).as<capnp::Text>().cStr();
      std::string error;
      auto json = json11::Json::parse(message, error);
      LogLine line{.time = time, .level = service == "errorLogMessage" ? 40 : 20, .source = service, .message = message};
      if (error.empty() && json.is_object()) {
        if (json["msg"].is_string()) line.message = json["msg"].string_value();
        if (json["levelnum"].is_number()) line.level = json["levelnum"].int_value();
        if (json["filename"].is_string()) line.source = json["filename"].string_value();
        line.wall = json["created"].number_value();
        line.context = json.dump();
      }
      logs.push_back(std::move(line));
    } else if (service == "thumbnail") {
      auto bytes = event.getThumbnail().getThumbnail();
      thumbnails.push_back({time, {bytes.begin(), bytes.end()}});
    }
  }
}

void Data::merge(Data batch) {
  if (!batch.revision) return;
  first = revision ? std::min(first, batch.first) : batch.first;
  last = std::max(last, batch.last);
  ++revision;
  for (auto &[name, channel] : batch.channels) {
    auto &target = channels[name];
    if (target.samples().empty()) {
      target = std::move(channel);
      continue;
    }
    auto &points = target.editSamples(target.samples().size() + channel.samples().size());
    size_t n = points.size();
    points.insert(points.end(), channel.samples().begin(), channel.samples().end());
    if (n && !channel.samples().empty() && points[n].time < points[n - 1].time)
      std::inplace_merge(points.begin(), points.begin() + n, points.end(), [](auto &a, auto &b) { return a.time < b.time; });
    target.labels.insert(channel.labels.begin(), channel.labels.end());
  }
  sent_frames.insert(sent_frames.end(), std::make_move_iterator(batch.sent_frames.begin()), std::make_move_iterator(batch.sent_frames.end()));
  std::stable_sort(sent_frames.begin(), sent_frames.end(), [](auto &a, auto &b) { return a.time < b.time; });
  logs.insert(logs.end(), std::make_move_iterator(batch.logs.begin()), std::make_move_iterator(batch.logs.end()));
  std::stable_sort(logs.begin(), logs.end(), [](auto &a, auto &b) { return a.time < b.time; });
  thumbnails.insert(thumbnails.end(), std::make_move_iterator(batch.thumbnails.begin()), std::make_move_iterator(batch.thumbnails.end()));
  std::stable_sort(thumbnails.begin(), thumbnails.end(), [](auto &a, auto &b) { return a.time < b.time; });
}

void Data::trim(double before) {
  for (auto &[_, channel] : channels) {
    auto &points = channel.editSamples();
    auto it = std::lower_bound(points.begin(), points.end(), before, [](auto &s, double t) { return s.time < t; });
    points.erase(points.begin(), it);
  }
  logs.erase(std::remove_if(logs.begin(), logs.end(), [before](auto &s) { return s.time < before; }), logs.end());
  thumbnails.erase(std::remove_if(thumbnails.begin(), thumbnails.end(), [before](auto &s) { return s.time < before; }), thumbnails.end());
  sent_frames.erase(std::remove_if(sent_frames.begin(), sent_frames.end(), [before](auto &s) { return s.time < before; }), sent_frames.end());
  first = std::max(first, before);
}

std::vector<Sample> transform(const Channel &source, double scale, double offset, bool derivative, double dt) {
  std::vector<Sample> result;
  result.reserve(source.samples().size());
  for (size_t i = derivative ? 1 : 0; i < source.samples().size(); ++i) {
    auto point = source.samples()[i];
    if (derivative) {
      double elapsed = dt > 0 ? dt : point.time - source.samples()[i - 1].time;
      if (elapsed <= 0) continue;
      point = {source.samples()[i - 1].time, (point.value - source.samples()[i - 1].value) / elapsed};
    }
    point.value = point.value * scale + offset;
    result.push_back(point);
  }
  return result;
}
}  // namespace cabana::analysis
