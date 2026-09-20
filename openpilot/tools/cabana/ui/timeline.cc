#include "tools/cabana/ui/timeline.h"

#include <cmath>
#include <cstdio>

#include "tools/cabana/core/playback.h"
#include "tools/cabana/core/source.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"

namespace {
std::string decimal(double value) {
  char buffer[64];
  snprintf(buffer, sizeof(buffer), "%.3f", value);
  return buffer;
}

// Extend the shared text field for seconds, retaining its fonts, spacing and focus behavior.
bool secondsInput(const char *id, std::string *text, double *value) {
  inputText(id, text, "Seconds", ImGuiInputTextFlags_CharsScientific | ImGuiInputTextFlags_EnterReturnsTrue);
  if (!ImGui::IsItemDeactivatedAfterEdit()) return false;
  try {
    size_t end = 0;
    const double parsed = std::stod(*text, &end);
    if (end == text->size() && std::isfinite(parsed)) {
      *value = parsed;
      *text = decimal(parsed);
      return true;
    }
  } catch (...) {}
  *text = decimal(*value);
  return false;
}
}

void PlaybackTimeline::setSources(const std::vector<AbstractStream *> &sources) {
  sources_.clear();
  for (auto *source : sources) if (!dynamic_cast<DummyStream *>(source)) sources_.push_back(source);
  if (sources_.empty()) selected_id_.clear();
  if (!selected() && !sources_.empty()) selected_id_ = sources_.front()->source_id;
  std::set<std::string> present;
  for (auto *source : sources_) {
    present.insert(source->source_id);
    if (auto *replay = dynamic_cast<ReplayStream *>(source)) replay->getReplay()->setLoop(false);
    if (!sliders_.count(source->source_id)) {
      // The shared transport owns looping; native route wrap would break linked offsets.
      if (auto *replay = dynamic_cast<ReplayStream *>(source)) replay->getReplay()->setLoop(false);
      sliders_.try_emplace(source->source_id);
      const std::string id = source->source_id;
      slider_connections_.emplace(id, sliders_.at(id).sliderReleased.connect([this, id]() {
        selectSource(id, selected_camera_);
        seek(sliders_.at(id).currentSecond());
        if (scrub_source_ == id) {
          if (scrub_resume_) for (auto *member : controlled()) { SourceScope scope(member); member->pause(false); }
          scrub_source_.clear();
        }
      }));
    }
  }
  for (auto it = sliders_.begin(); it != sliders_.end();) {
    if (present.count(it->first)) { ++it; continue; }
    linked_.erase(it->first);
    slider_connections_.erase(it->first);
    offset_inputs_.erase(it->first);
    filmstrips_.erase(it->first);
    it = sliders_.erase(it);
  }
}

AbstractStream *PlaybackTimeline::source(const std::string &id) const {
  for (auto *member : sources_) if (member->source_id == id) return member;
  return nullptr;
}

AbstractStream *PlaybackTimeline::selected() const { return source(selected_id_); }

void PlaybackTimeline::selectSource(const std::string &id, VisionStreamType camera) {
  ++selection_revision_;
  selected_id_ = id;
  selected_camera_ = camera;
  if (linked_.count(id)) linked_master_id_ = id;
}

std::vector<AbstractStream *> PlaybackTimeline::controlled() const {
  return controlled(selected());
}

std::vector<AbstractStream *> PlaybackTimeline::controlled(AbstractStream *master) const {
  if (!master) return {};
  if (!linked_.count(master->source_id) || master->liveStreaming()) return {master};
  std::vector<AbstractStream *> result;
  for (auto *source : sources_) {
    if (!source->liveStreaming() && linked_.count(source->source_id)) result.push_back(source);
  }
  return result;
}

std::pair<double, double> PlaybackTimeline::groupRange() const {
  return groupRange(selected());
}

std::pair<double, double> PlaybackTimeline::groupRange(AbstractStream *master) const {
  std::vector<std::pair<double, double>> ranges;
  for (auto *source : controlled(master)) {
    ranges.emplace_back(source->minSeconds() + source->timeline_offset, source->maxSeconds() + source->timeline_offset);
  }
  return cabana::playback::sharedRange(ranges).value_or(std::make_pair(1., 0.));
}

void PlaybackTimeline::seek(double route_seconds) { seekGroup(selected(), route_seconds); }

void PlaybackTimeline::seekGroup(AbstractStream *master, double route_seconds) {
  if (!master) return;
  auto [begin, end] = groupRange(master);
  if (begin > end) { status_ = "Linked routes do not overlap. Align their current positions."; return; }
  const double time = std::clamp(route_seconds + master->timeline_offset, begin, end);
  for (auto *source : controlled(master)) {
    SourceScope scope(source);
    source->seekTo(time - source->timeline_offset);
  }
  last_sync_ = ImGui::GetTime();
}

void PlaybackTimeline::setPaused(bool paused) {
  for (auto *source : controlled()) { SourceScope scope(source); source->pause(paused); }
}

void PlaybackTimeline::togglePlayback() {
  auto *master = selected();
  if (!master) return;
  const bool paused = !master->isPaused();
  const auto range = groupRange();
  if (!paused && !master->liveStreaming() && range.first > range.second) {
    status_ = "Linked routes do not overlap. Align their current positions.";
    return;
  }
  if (!paused && !master->liveStreaming()) {
    double position = master->currentSec() + master->timeline_offset;
    if (position < range.first || position >= range.second - 0.001) seek(range.first - master->timeline_offset);
  }
  const float speed = master->getSpeed();
  for (auto *source : controlled()) {
    SourceScope scope(source);
    source->setSpeed(speed);
    source->pause(paused);
  }
}

void PlaybackTimeline::stepFrame(bool forward) {
  auto *master = selected();
  if (!master || master->liveStreaming()) return;
  for (auto *source : controlled()) { SourceScope scope(source); source->pause(true); }
  auto *replay = dynamic_cast<ReplayStream *>(master);
  const CameraType camera = selected_camera_ == VISION_STREAM_CABIN ? CabinCam :
                            selected_camera_ == VISION_STREAM_WIDE_ROAD ? WideRoadCam : NarrowRoadCam;
  auto target = replay ? replay->nextFrameTime(camera, master->currentSec(), forward) : std::nullopt;
  if (!target) {
    status_ = "No adjacent camera frame is loaded at this position.";
    return;
  }
  status_.clear();
  seek(*target);
}

void PlaybackTimeline::alignCurrentPositions() {
  auto *master = selected();
  if (!master || master->liveStreaming()) return;
  // With no group chosen, the action links every open route in one click.
  if (controlled().size() < 2) {
    for (auto *source : sources_) if (!source->liveStreaming()) linked_.insert(source->source_id);
  }
  const double time = master->currentSec() + master->timeline_offset;
  for (auto *source : controlled()) {
    SourceScope scope(source);
    source->pause(true);
    source->timeline_offset = time - source->currentSec();
    offset_inputs_[source->source_id] = decimal(source->timeline_offset);
  }
  status_ = "Current positions aligned. Linked routes now move together.";
}

void PlaybackTimeline::setSpeed(float speed) {
  for (auto *source : controlled()) { SourceScope scope(source); source->setSpeed(speed); }
}

bool PlaybackTimeline::loopApplies(AbstractStream *master) const {
  if (!loop_ || !master) return false;
  return master->source_id == loop_source_id_ ||
         (linked_.count(master->source_id) && linked_.count(loop_source_id_));
}

void PlaybackTimeline::tick() {
  if (ImGui::GetTime() - last_sync_ < 0.20) return;
  last_sync_ = ImGui::GetTime();
  std::vector<std::string> linked_members;
  for (auto *member : sources_) {
    if (!member->liveStreaming() && linked_.count(member->source_id)) linked_members.push_back(member->source_id);
  }
  linked_master_id_ = cabana::playback::linkedMaster(linked_master_id_, selected_id_, linked_members);
  auto *linked_master = source(linked_master_id_);
  // Selection controls toolbar actions. Every running group retains its own
  // clock and loop when the user inspects or controls an unrelated source.
  for (auto *master : sources_) {
    if (master->liveStreaming() || (linked_.count(master->source_id) && master != linked_master)) continue;
    const auto members = controlled(master);
    const auto range = groupRange(master);
    if (range.first > range.second) {
      for (auto *member : members) {
        if (!member->isPaused()) { SourceScope scope(member); member->pause(true); }
      }
      status_ = "Linked routes do not overlap. Align their current positions.";
      continue;
    }
    const double time = master->currentSec() + master->timeline_offset;
    if (!master->isPaused()) {
      const auto interval = loopApplies(master) ? cabana::playback::loopRange(loop_start_, loop_end_, range) : std::nullopt;
      if (interval && (time >= interval->second || time < interval->first)) {
        seekGroup(master, interval->first - master->timeline_offset);
        continue;
      }
      if (time >= range.second - 0.001) {
        for (auto *member : members) { SourceScope scope(member); member->pause(true); }
        continue;
      }
    }
    for (auto *member : members) {
      if (member == master) continue;
      SourceScope scope(member);
      if (member->isPaused() != master->isPaused()) member->pause(master->isPaused());
      if (std::abs(member->getSpeed() - master->getSpeed()) > 0.001) member->setSpeed(master->getSpeed());
      const double target = std::clamp(time - member->timeline_offset, member->minSeconds(), member->maxSeconds());
      if (std::abs(member->currentSec() - target) > (master->isPaused() ? 0.002 : 0.15)) member->seekTo(target);
    }
  }
}

void PlaybackTimeline::handleShortcuts() {
  if (ImGui::GetIO().WantTextInput || ImGui::IsAnyItemActive() || ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) return;
  if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) togglePlayback();
  if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) stepFrame(false);
  if (ImGui::IsKeyPressed(ImGuiKey_RightArrow)) stepFrame(true);
}

float PlaybackTimeline::height(size_t max_tracks) const {
  const auto &style = ImGui::GetStyle();
  return style.WindowPadding.y * 2 + ImGui::GetFrameHeightWithSpacing() +
         108.f * std::min(sources_.size(), max_tracks) +
         (status_.empty() ? 0 : ImGui::GetTextLineHeightWithSpacing());
}

void PlaybackTimeline::drawSettings() {
  if (dropdown::Item("Align current positions", nullptr, false, sources_.size() > 1)) alignCurrentPositions();
  if (dropdown::Item("Unlink all routes", nullptr, false, !linked_.empty())) linked_.clear();
  ImGui::Separator();
  if (dropdown::Item("Loop selected interval", nullptr, loopApplies(selected()))) {
    loop_ = !loopApplies(selected());
    if (loop_) loop_source_id_ = selected_id_;
  }
  if (dropdown::Item("Loop next 10 seconds")) {
    if (auto *master = selected()) {
      const auto range = groupRange();
      loop_start_ = std::clamp(master->currentSec() + master->timeline_offset, range.first, std::max(range.first, range.second));
      loop_end_ = std::min(loop_start_ + 10., range.second);
      loop_start_input_ = decimal(loop_start_);
      loop_end_input_ = decimal(loop_end_);
      loop_ = loop_end_ > loop_start_;
      loop_source_id_ = master->source_id;
    }
  }
  ImGui::Separator();
  ImGui::TextDisabled("Interval in workspace seconds");
  ImGui::SetNextItemWidth(110);
  secondsInput("Start", &loop_start_input_, &loop_start_);
  ImGui::SetNextItemWidth(110);
  secondsInput("End", &loop_end_input_, &loop_end_);
  if (loop_end_ <= loop_start_) ImGui::TextDisabled("End must be later than start.");
}

void PlaybackTimeline::drawTrack(AbstractStream *source) {
  SourceScope scope(source);
  ImGui::PushID(source->source_id.c_str());
  ImGui::TableNextRow(0, 100);
  ImGui::TableSetColumnIndex(0);
  const bool active = source == selected();
  const std::string label = source->source_label.empty() ? source->routeName() : source->source_label;
  pushBoldFont();
  if (elidedSelectable("source", label, active)) selectSource(source->source_id);
  popBoldFont();
  const auto route_name = source->routeName();
  const auto tooltip = label == route_name || route_name.empty() ? label : label + "\n" + route_name;
  ImGui::SetItemTooltip("%s\nClick to control this source. Space: play/pause. Arrow keys: previous/next camera frame.", tooltip.c_str());
  ImGui::Indent(ImGui::GetStyle().FramePadding.x);
  pushMonoFont();
  ImGui::TextUnformatted(utils::formatSeconds(source->currentSec(), true, false).c_str());
  popMonoFont();
  if (source->liveStreaming()) {
    ImGui::SameLine();
    if (iconButton("go-live", icon::SKIP_END, "Go live")) { source->pause(false); source->seekTo(source->maxSeconds() + 1); }
  } else {
    bool linked = linked_.count(source->source_id);
    if (checkBox("Link", &linked)) {
      if (linked) linked_.insert(source->source_id); else linked_.erase(source->source_id);
    }
    ImGui::SetItemTooltip("Play checked routes together. Use Options → Align current positions to synchronize events.");
    ImGui::SameLine();
    auto [it, inserted] = offset_inputs_.try_emplace(source->source_id, decimal(source->timeline_offset));
    const float suffix_width = ImGui::CalcTextSize("s").x + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetNextItemWidth(std::max(1.f, std::min(ImGui::CalcTextSize("-000.000").x + ImGui::GetStyle().FramePadding.x * 2,
                                               ImGui::GetContentRegionAvail().x - suffix_width)));
    if (secondsInput("##offset", &it->second, &source->timeline_offset)) status_.clear();
    ImGui::SetItemTooltip("Alignment offset in seconds. Workspace time = route time + offset.");
    ImGui::SameLine();
    ImGui::TextDisabled("s");
  }
  ImGui::Unindent(ImGui::GetStyle().FramePadding.x);
  ImGui::TableSetColumnIndex(1);
  // A ruler and one continuous clip make the route read like a video editing track.
  auto *ruler_draw = ImGui::GetWindowDrawList();
  const ImVec2 ruler = ImGui::GetCursorScreenPos();
  const float track_width = ImGui::GetContentRegionAvail().x;
  const double duration = source->maxSeconds() - source->minSeconds();
  const double raw_step = std::max(.001, duration / std::max(1.f, track_width / 90.f));
  const double magnitude = std::pow(10., std::floor(std::log10(raw_step)));
  const double step = magnitude * (raw_step / magnitude <= 1 ? 1 : raw_step / magnitude <= 2 ? 2 : raw_step / magnitude <= 5 ? 5 : 10);
  for (double seconds = std::ceil(source->minSeconds() / step) * step; seconds <= source->maxSeconds(); seconds += step) {
    const float x = ruler.x + track_width * (seconds - source->minSeconds()) / std::max(.001, duration);
    const auto tick_label = utils::formatSeconds(seconds, step < 1, false);
    const float text_width = ImGui::CalcTextSize(tick_label.c_str()).x;
    ruler_draw->AddText(ImVec2(std::clamp(x - text_width / 2, ruler.x, std::max(ruler.x, ruler.x + track_width - text_width)), ruler.y),
                       ImGui::GetColorU32(ImGuiCol_TextDisabled), tick_label.c_str());
    ruler_draw->AddLine(ImVec2(x, ruler.y + 16), ImVec2(x, ruler.y + 20), ImGui::GetColorU32(ImGuiCol_Border));
  }
  ImGui::Dummy(ImVec2(track_width, 18));
  auto &filmstrip = filmstrips_[source->source_id];
  if (!filmstrip) filmstrip = std::make_unique<RouteFilmstrip>();
  filmstrip->update(dynamic_cast<ReplayStream *>(source));
  auto &slider = sliders_.at(source->source_id);
  slider.setTimeRange(source->minSeconds(), source->maxSeconds());
  if (!slider.isSliderDown()) slider.setCurrentSecond(source->currentSec());
  slider.drawFilmstrip(track_width, 68, [&](ImDrawList *draw, ImVec2 min, ImVec2 max) {
    filmstrip->draw(draw, min, max);
    if (loopApplies(source) && duration > 0) {
      const auto x = [&](double seconds) { return min.x + float(std::clamp((seconds - source->timeline_offset - source->minSeconds()) / duration, 0., 1.)) * (max.x - min.x); };
      const float left = x(loop_start_), right = x(loop_end_);
      if (right > left) {
        draw->AddRectFilled(min, ImVec2(left, max.y), IM_COL32(0, 0, 0, 125));
        draw->AddRectFilled(ImVec2(right, min.y), max, IM_COL32(0, 0, 0, 125));
        draw->AddRect(ImVec2(left, min.y), ImVec2(right, max.y), IM_COL32(255, 200, 70, 230), 0, 0, 2);
      }
    }
  }, active);
  if (slider.isSliderDown()) {
    if (scrub_source_ != source->source_id) {
      selectSource(source->source_id, selected_camera_);
      scrub_source_ = source->source_id;
      scrub_resume_ = !source->isPaused();
      for (auto *member : controlled()) { SourceScope member_scope(member); member->pause(true); }
      scrub_preview_time_ = 0;
    }
    // Preview while dragging, bounded to ten seeks per second to keep decoding responsive.
    if (ImGui::GetTime() - scrub_preview_time_ >= 0.1) {
      seek(slider.currentSecond());
      scrub_preview_time_ = ImGui::GetTime();
    }
  }
  if (ImGui::IsItemHovered()) {
    const double hover_time = source->minSeconds() + duration * std::clamp((ImGui::GetMousePos().x - slider.rect().Min.x) / slider.width(), 0.f, 1.f);
    ImGui::SetTooltip("%s · %s\nDrag to scrub · Left / Right to step a frame", label.c_str(),
                      utils::formatSeconds(hover_time, true, false).c_str());
  }
  ImGui::PopID();
}

void PlaybackTimeline::draw(bool expanded) {
  auto *master = selected();
  if (!master) {
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Open a route or connect a live source to begin.");
    return;
  }
  SourceScope scope(master);
  std::vector<ToolbarItem> items;
  items.push_back(toolbarAction("prev-frame", icon::REWIND, "Previous camera frame (Left)", [this]() { stepFrame(false); }, !master->liveStreaming()));
  items.push_back(toolbarAction("play", master->isPaused() ? icon::PLAY : icon::PAUSE, "Play / pause (Space)", [this]() { togglePlayback(); }));
  items.push_back(toolbarAction("next-frame", icon::FAST_FORWARD, "Next camera frame (Right)", [this]() { stepFrame(true); }, !master->liveStreaming()));
  char speed_label[24];
  snprintf(speed_label, sizeof(speed_label), "%gx", master->getSpeed());
  items.push_back(toolbarMenu("speed", speed_label, "Playback speed", [this, master]() {
    for (const float speed : {0.05f, 0.1f, 0.25f, 0.5f, 1.f, 2.f, 5.f}) {
      char label[20]; snprintf(label, sizeof(label), "%gx", speed);
      if (dropdown::Item(label, nullptr, std::abs(master->getSpeed() - speed) < .001)) setSpeed(speed);
    }
  }));
  items.push_back(toolbarMenu("timeline-settings", loopApplies(master) ? "Options · Loop on" : "Options", "Synchronization and loop interval", [this]() { drawSettings(); }));
  drawToolbar(items, 3);
  if (!expanded) return;
  if (!status_.empty()) {
    ImGui::TextDisabled("%s", status_.c_str());
    if (ImGui::IsItemClicked()) status_.clear();
  }
  if (ImGui::BeginTable("source-tracks", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp, ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 210);
    ImGui::TableSetupColumn("Video", ImGuiTableColumnFlags_WidthStretch);
    for (auto *source : sources_) drawTrack(source);
    ImGui::EndTable();
  }
}

json11::Json PlaybackTimeline::snapshot() const {
  json11::Json::array linked;
  json11::Json::object offsets, positions;
  for (auto *source : sources_) {
    offsets[source->source_id] = source->timeline_offset;
    positions[source->source_id] = source->currentSec();
    if (linked_.count(source->source_id)) linked.push_back(source->source_id);
  }
  return json11::Json::object{{"selected", selected_id_}, {"camera", (int)selected_camera_}, {"linked", linked},
                            {"positions", positions}, {"offsets", offsets}, {"linked_master", linked_master_id_},
                            {"loop_source", loop_source_id_}, {"loop", loop_}, {"loop_start", loop_start_}, {"loop_end", loop_end_}};
}

void PlaybackTimeline::restore(const json11::Json &state) {
  selected_id_ = state["selected"].string_value();
  if (!selected() && !sources_.empty()) selected_id_ = sources_.front()->source_id;
  int camera = state["camera"].int_value();
  selected_camera_ = camera >= VISION_STREAM_NARROW_ROAD && camera <= VISION_STREAM_WIDE_ROAD ? (VisionStreamType)camera : VISION_STREAM_NARROW_ROAD;
  linked_.clear();
  for (const auto &id : state["linked"].array_items()) if (id.is_string()) linked_.insert(id.string_value());
  for (auto *source : sources_) {
    const auto &offset = state["offsets"][source->source_id];
    source->timeline_offset = offset.is_number() && std::isfinite(offset.number_value()) ? offset.number_value() : 0;
    const auto &position = state["positions"][source->source_id];
    if (!source->liveStreaming() && position.is_number() && std::isfinite(position.number_value())) {
      SourceScope scope(source);
      source->pause(true);
      source->seekTo(std::clamp(position.number_value(), source->minSeconds(), source->maxSeconds()));
    }
  }
  linked_master_id_ = state["linked_master"].is_string() ? state["linked_master"].string_value() : selected_id_;
  loop_source_id_ = state["loop_source"].is_string() ? state["loop_source"].string_value() : selected_id_;
  offset_inputs_.clear();
  loop_start_ = state["loop_start"].number_value();
  loop_end_ = state["loop_end"].is_number() ? state["loop_end"].number_value() : 10;
  loop_ = state["loop"].bool_value() && std::isfinite(loop_start_) && std::isfinite(loop_end_) && loop_end_ > loop_start_;
  loop_start_input_ = decimal(loop_start_);
  loop_end_input_ = decimal(loop_end_);
  status_.clear();
}
