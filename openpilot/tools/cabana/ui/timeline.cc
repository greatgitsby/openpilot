#include "tools/cabana/ui/timeline.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iterator>

#include "tools/cabana/core/source.h"
#include "tools/cabana/streams/replaystream.h"
#include "tools/cabana/ui/icons.h"
#include "tools/cabana/ui/util.h"
#include "tools/cabana/utils/strings.h"

namespace {
constexpr const char *NO_OVERLAP = "Linked routes do not overlap. Align their current positions.";

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

template <typename Container, typename Keep>
void keepIf(Container &items, Keep keep) {
  for (auto it = items.begin(); it != items.end();) it = keep(*it) ? std::next(it) : items.erase(it);
}
}  // namespace

void PlaybackTimeline::setSources(const std::vector<AbstractStream *> &sources) {
  sources_.clear();
  slots_.clear();
  for (auto *source : sources) {
    if (dynamic_cast<DummyStream *>(source)) { slots_.push_back(source->source_id); continue; }
    sources_.push_back(source);
    // The shared transport owns looping; native route wrap would break linked offsets.
    if (auto *replay = dynamic_cast<ReplayStream *>(source)) replay->getReplay()->setLoop(false);
    if (!filmstrips_[source->source_id]) {
      filmstrips_[source->source_id] = std::make_unique<RouteFilmstrip>();
      restoreSource(source);
    }
  }
  if (!selected()) selected_id_ = sources_.empty() ? "" : sources_.front()->source_id;
  keepIf(linked_, [this](const auto &id) { return source(id); });
  keepIf(filmstrips_, [this](const auto &item) { return source(item.first); });
  keepIf(offset_inputs_, [this](const auto &item) { return source(item.first); });
}

AbstractStream *PlaybackTimeline::source(const std::string &id) const {
  for (auto *member : sources_) if (member->source_id == id) return member;
  return nullptr;
}

void PlaybackTimeline::selectSource(const std::string &id, VisionStreamType camera) {
  ++selection_revision_;
  selected_id_ = id;
  selected_camera_ = camera;
  if (linked_.count(id)) linked_master_id_ = id;
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

// The intersection of the group's ranges in workspace time; begin > end when they do not overlap.
std::pair<double, double> PlaybackTimeline::groupRange(AbstractStream *master) const {
  std::pair<double, double> range{-INFINITY, INFINITY};
  for (auto *source : controlled(master)) {
    range.first = std::max(range.first, source->minSeconds() + source->timeline_offset);
    range.second = std::min(range.second, source->maxSeconds() + source->timeline_offset);
  }
  return std::isfinite(range.first) && std::isfinite(range.second) && range.first <= range.second ? range : std::make_pair(1., 0.);
}

void PlaybackTimeline::seek(double route_seconds) { seekGroup(selected(), route_seconds); }

void PlaybackTimeline::seekGroup(AbstractStream *master, double route_seconds) {
  if (!master) return;
  auto [begin, end] = groupRange(master);
  if (begin > end) { status_ = NO_OVERLAP; return; }
  const double time = std::clamp(route_seconds + master->timeline_offset, begin, end);
  for (auto *source : controlled(master)) {
    SourceScope scope(source);
    source->seekTo(time - source->timeline_offset);
  }
  last_sync_ = ImGui::GetTime();
}

void PlaybackTimeline::setPaused(bool paused) {
  for (auto *source : controlled(selected())) { SourceScope scope(source); source->pause(paused); }
}

void PlaybackTimeline::togglePlayback() {
  auto *master = selected();
  if (!master) return;
  const bool paused = !master->isPaused();
  if (!paused && !master->liveStreaming()) {
    const auto range = groupRange(master);
    if (range.first > range.second) { status_ = NO_OVERLAP; return; }
    const double position = master->currentSec() + master->timeline_offset;
    if (position < range.first || position >= range.second - 0.001) seek(range.first - master->timeline_offset);
  }
  for (auto *source : controlled(master)) {
    SourceScope scope(source);
    source->setSpeed(master->getSpeed());
    source->pause(paused);
  }
}

void PlaybackTimeline::stepFrame(bool forward) {
  auto *master = selected();
  if (!master || master->liveStreaming()) return;
  setPaused(true);
  auto *replay = dynamic_cast<ReplayStream *>(master);
  CameraType camera = selected_camera_ == VISION_STREAM_CABIN ? CabinCam :
                      selected_camera_ == VISION_STREAM_WIDE_ROAD ? WideRoadCam : NarrowRoadCam;
  if (replay && !replay->availableCameras().count(camera)) camera = NarrowRoadCam;
  auto target = replay ? replay->nextFrameTime(camera, master->currentSec(), forward) : std::nullopt;
  status_ = target ? "" : "No adjacent camera frame is loaded at this position.";
  if (target) seek(*target);
}

void PlaybackTimeline::alignCurrentPositions() {
  auto *master = selected();
  if (!master || master->liveStreaming()) return;
  // With no group chosen, the action links every open route in one click.
  if (controlled(master).size() < 2) {
    for (auto *source : sources_) if (!source->liveStreaming()) linked_.insert(source->source_id);
  }
  const double time = master->currentSec() + master->timeline_offset;
  for (auto *source : controlled(master)) {
    SourceScope scope(source);
    source->pause(true);
    source->timeline_offset = time - source->currentSec();
    offset_inputs_[source->source_id] = decimal(source->timeline_offset);
  }
  status_ = "Current positions aligned. Linked routes now move together.";
}

bool PlaybackTimeline::loopApplies(AbstractStream *master) const {
  if (!loop_ || !master) return false;
  return master->source_id == loop_source_id_ ||
         (linked_.count(master->source_id) && linked_.count(loop_source_id_));
}

void PlaybackTimeline::tick() {
  if (ImGui::GetTime() - last_sync_ < 0.20) return;
  last_sync_ = ImGui::GetTime();
  // Keep a linked group's clock independent of selection in other groups.
  std::vector<std::string> members;
  for (auto *member : sources_) {
    if (!member->liveStreaming() && linked_.count(member->source_id)) members.push_back(member->source_id);
  }
  auto is_member = [&](const std::string &id) { return std::find(members.begin(), members.end(), id) != members.end(); };
  if (!is_member(linked_master_id_)) linked_master_id_ = is_member(selected_id_) ? selected_id_ : members.empty() ? "" : members.front();
  // Every running group retains its own clock and loop when the user inspects or controls an unrelated source.
  for (auto *master : sources_) {
    if (master->liveStreaming() || (linked_.count(master->source_id) && master->source_id != linked_master_id_)) continue;
    const auto group = controlled(master);
    const auto [begin, end] = groupRange(master);
    if (begin > end) {
      for (auto *member : group) if (!member->isPaused()) { SourceScope scope(member); member->pause(true); }
      status_ = NO_OVERLAP;
      continue;
    }
    const double time = master->currentSec() + master->timeline_offset;
    if (!master->isPaused()) {
      const double loop_begin = std::max(begin, loop_start_), loop_end = std::min(end, loop_end_);
      if (loopApplies(master) && loop_end - loop_begin >= 0.001 && (time >= loop_end || time < loop_begin)) {
        seekGroup(master, loop_begin - master->timeline_offset);
        continue;
      }
      if (time >= end - 0.001) {
        for (auto *member : group) { SourceScope scope(member); member->pause(true); }
        continue;
      }
    }
    for (auto *member : group) {
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
  if (auto *master = selected(); dropdown::Item("Loop next 10 seconds", nullptr, false, master)) {
    const auto [begin, end] = groupRange(master);
    loop_start_ = std::clamp(master->currentSec() + master->timeline_offset, begin, std::max(begin, end));
    loop_end_ = std::min(loop_start_ + 10., end);
    loop_start_input_ = decimal(loop_start_);
    loop_end_input_ = decimal(loop_end_);
    loop_ = loop_end_ > loop_start_;
    loop_source_id_ = master->source_id;
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
  const std::string id = source->source_id;
  ImGui::PushID(id.c_str());
  ImGui::TableNextRow(0, 100);
  ImGui::TableSetColumnIndex(0);
  const bool active = source == selected();
  const std::string label = source->source_label.empty() ? source->routeName() : source->source_label;
  pushBoldFont();
  if (elidedSelectable("source", label, active)) selectSource(id);
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
    bool linked = linked_.count(id);
    if (checkBox("Link", &linked)) {
      if (linked) linked_.insert(id); else linked_.erase(id);
    }
    ImGui::SetItemTooltip("Play checked routes together. Use Options → Align current positions to synchronize events.");
    ImGui::SameLine();
    auto [it, inserted] = offset_inputs_.try_emplace(id, decimal(source->timeline_offset));
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
  ImDrawList *draw = ImGui::GetWindowDrawList();
  const ImVec2 ruler = ImGui::GetCursorScreenPos();
  const float track_width = std::max(1.f, ImGui::GetContentRegionAvail().x);
  const double begin = source->minSeconds(), end = source->maxSeconds(), duration = std::max(.001, end - begin);
  const double raw_step = std::max(.001, duration / std::max(1.f, track_width / 90.f));
  const double magnitude = std::pow(10., std::floor(std::log10(raw_step)));
  const double step = magnitude * (raw_step / magnitude <= 1 ? 1 : raw_step / magnitude <= 2 ? 2 : raw_step / magnitude <= 5 ? 5 : 10);
  const auto x_at = [&](double seconds) { return ruler.x + track_width * float(std::clamp((seconds - begin) / duration, 0., 1.)); };
  for (double seconds = std::ceil(begin / step) * step; seconds <= end; seconds += step) {
    const auto tick_label = utils::formatSeconds(seconds, step < 1, false);
    const float text_width = ImGui::CalcTextSize(tick_label.c_str()).x;
    draw->AddText(ImVec2(std::clamp(x_at(seconds) - text_width / 2, ruler.x, std::max(ruler.x, ruler.x + track_width - text_width)), ruler.y),
                  ImGui::GetColorU32(ImGuiCol_TextDisabled), tick_label.c_str());
    draw->AddLine(ImVec2(x_at(seconds), ruler.y + 16), ImVec2(x_at(seconds), ruler.y + 20), ImGui::GetColorU32(ImGuiCol_Border));
  }
  ImGui::Dummy(ImVec2(track_width, 18));

  auto &filmstrip = *filmstrips_.at(id);
  filmstrip.update(dynamic_cast<ReplayStream *>(source));
  ImGui::InvisibleButton("##clip", ImVec2(track_width, 68));
  const ImRect clip(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
  const double mouse_time = begin + duration * std::clamp((ImGui::GetMousePos().x - clip.Min.x) / clip.GetWidth(), 0.f, 1.f);
  const bool scrubbing = ImGui::IsItemActive(), released = ImGui::IsItemDeactivated(), hovered = ImGui::IsItemHovered();
  if (ImGui::IsItemActivated()) {
    selectSource(id, selected_camera_);
    scrub_resume_ = !source->isPaused();
    scrub_preview_time_ = 0;
    setPaused(true);
  }
  // Preview while dragging, bounded to ten seeks per second to keep decoding responsive.
  if (scrubbing && ImGui::GetTime() - scrub_preview_time_ >= 0.1) {
    seek(mouse_time);
    scrub_preview_time_ = ImGui::GetTime();
  }
  if (released) {
    seek(mouse_time);
    if (scrub_resume_) setPaused(false);
  }
  if (hovered) {
    ImGui::SetTooltip("%s · %s\nDrag to scrub · Left / Right to step a frame", label.c_str(), utils::formatSeconds(mouse_time, true, false).c_str());
  }

  draw->PushClipRect(clip.Min, clip.Max, true);
  draw->AddRectFilled(clip.Min, clip.Max, ImGui::GetColorU32(ImGuiCol_FrameBg));
  filmstrip.draw(draw, clip.Min, clip.Max);
  if (loopApplies(source)) {
    const float left = x_at(loop_start_ - source->timeline_offset), right = x_at(loop_end_ - source->timeline_offset);
    if (right > left) {
      draw->AddRectFilled(clip.Min, ImVec2(left, clip.Max.y), IM_COL32(0, 0, 0, 125));
      draw->AddRectFilled(ImVec2(right, clip.Min.y), clip.Max, IM_COL32(0, 0, 0, 125));
      draw->AddRect(ImVec2(left, clip.Min.y), ImVec2(right, clip.Max.y), IM_COL32(255, 200, 70, 230), 0, 0, 2);
    }
  }
  // Event ribbon: engagement and alerts, dimmed where segments are not loaded. The edges snap to whole
  // pixels with an inclusive right edge, so an event shorter than a pixel still paints one full pixel.
  const float ribbon_top = clip.Max.y - 8.f;
  auto fill = [&](double from, double to, ImU32 color) {
    if (from <= end && to >= begin) draw->AddRectFilled(ImVec2(std::floor(x_at(from)), ribbon_top), ImVec2(std::floor(x_at(to)) + 1, clip.Max.y), color);
  };
  auto event_color = [](TimelineType type) {
    return toImU32(graphicColor(fromImVec4(ImGui::ColorConvertU32ToFloat4(timelineColor(type))), palette().window));
  };
  draw->AddRectFilled(ImVec2(clip.Min.x, ribbon_top), clip.Max, event_color(TimelineType::None));
  if (auto *replay = dynamic_cast<ReplayStream *>(source)) {
    for (const auto &entry : *replay->getReplay()->getTimeline()) fill(entry.start_time, entry.end_time, event_color(entry.type));
    const auto data = replay->getReplay()->getEventData();
    for (const auto &[n, _] : replay->getReplay()->route().segments()) {
      if (!data->isSegmentLoaded(n)) fill(n * 60.0, (n + 1) * 60.0, ImGui::GetColorU32(ImGuiCol_WindowBg, 160 / 255.0f));
    }
  }
  const float x = std::max(clip.Min.x + 1.f, x_at(scrubbing ? mouse_time : source->currentSec()));
  draw->AddLine(ImVec2(x + 1, clip.Min.y), ImVec2(x + 1, clip.Max.y), IM_COL32(0, 0, 0, 160), 3.0f);
  draw->AddLine(ImVec2(x, clip.Min.y), ImVec2(x, clip.Max.y), IM_COL32(255, 255, 255, 245), 2.0f);
  draw->AddTriangleFilled(ImVec2(x - 5, clip.Min.y), ImVec2(x + 5, clip.Min.y), ImVec2(x, clip.Min.y + 6), IM_COL32(255, 255, 255, 245));
  draw->PopClipRect();
  draw->AddRect(clip.Min, clip.Max, ImGui::GetColorU32(active ? ImGuiCol_SliderGrabActive : ImGuiCol_Border), 2.0f, 0, active ? 2.0f : 1.0f);
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
      if (dropdown::Item(label, nullptr, std::abs(master->getSpeed() - speed) < .001)) {
        for (auto *member : controlled(master)) { SourceScope member_scope(member); member->setSpeed(speed); }
      }
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
  for (const auto &id : slots_) {
    if (saved_["offsets"][id].is_number()) offsets[id] = saved_["offsets"][id];
    if (saved_["positions"][id].is_number()) positions[id] = saved_["positions"][id];
    for (const auto &link : saved_["linked"].array_items()) if (link == id) linked.push_back(id);
  }
  return json11::Json::object{{"selected", selected_id_}, {"camera", (int)selected_camera_}, {"linked", linked},
                            {"positions", positions}, {"offsets", offsets}, {"linked_master", linked_master_id_},
                            {"loop_source", loop_source_id_}, {"loop", loop_}, {"loop_start", loop_start_}, {"loop_end", loop_end_}};
}

// A source's saved offset, link, and position apply when it is restored or its route first loads.
void PlaybackTimeline::restoreSource(AbstractStream *source) {
  const auto &offset = saved_["offsets"][source->source_id];
  source->timeline_offset = offset.is_number() && std::isfinite(offset.number_value()) ? offset.number_value() : 0;
  for (const auto &id : saved_["linked"].array_items()) if (id == source->source_id) linked_.insert(source->source_id);
  const auto &position = saved_["positions"][source->source_id];
  if (!source->liveStreaming() && position.is_number() && std::isfinite(position.number_value())) {
    SourceScope scope(source);
    source->pause(true);
    source->seekTo(std::clamp(position.number_value(), source->minSeconds(), source->maxSeconds()));
  }
}

void PlaybackTimeline::renameSource(const std::string &from, const std::string &to) {
  for (auto *id : {&linked_master_id_, &loop_source_id_}) if (*id == from) *id = to;
}

void PlaybackTimeline::restore(const json11::Json &state) {
  saved_ = state;
  selected_id_ = state["selected"].string_value();
  if (!selected()) selected_id_ = sources_.empty() ? "" : sources_.front()->source_id;
  const int camera = state["camera"].int_value();
  selected_camera_ = camera >= VISION_STREAM_NARROW_ROAD && camera <= VISION_STREAM_WIDE_ROAD ? (VisionStreamType)camera : VISION_STREAM_NARROW_ROAD;
  linked_.clear();
  for (auto *source : sources_) restoreSource(source);
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
