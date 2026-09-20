#include <limits>

#include "common/tests/native_test.h"
#include "tools/cabana/core/playback.h"

void test_playback_ranges() {
  using cabana::playback::linkedMaster;
  // A/B keep their playback clock when C becomes the toolbar target. Removing
  // the clock source elects a surviving member, never the unrelated selection.
  REQUIRE(linkedMaster("A", "C", {"A", "B"}) == "A");
  REQUIRE(linkedMaster("A", "C", {"B"}) == "B");
  REQUIRE(linkedMaster("", "B", {"A", "B"}) == "B");
  REQUIRE(linkedMaster("A", "C", {}).empty());
  using cabana::playback::sharedRange;
  using cabana::playback::loopRange;
  REQUIRE(!sharedRange({}));
  // Route B begins 15 seconds later in workspace time; seeking the group must
  // not push A or B beyond their available data.
  const auto synchronized = sharedRange({{0, 60}, {15, 75}});
  REQUIRE(synchronized.has_value());
  REQUIRE(synchronized->first == 15);
  REQUIRE(synchronized->second == 60);
  REQUIRE(!sharedRange({{0, 10}, {11, 20}}));
  REQUIRE(!sharedRange({{10, 0}}));
  REQUIRE(!sharedRange({{0, std::numeric_limits<double>::infinity()}}));
  REQUIRE(!sharedRange({{std::numeric_limits<double>::quiet_NaN(), 10}}));

  const auto clipped_loop = loopRange(55, 65, *synchronized);
  REQUIRE(clipped_loop.has_value());
  REQUIRE(clipped_loop->first == 55);
  REQUIRE(clipped_loop->second == 60);
  REQUIRE(!loopRange(70, 80, *synchronized));
  REQUIRE(!loopRange(40, 40, *synchronized));
  REQUIRE(!loopRange(50, 40, *synchronized));
  REQUIRE(!loopRange(0, std::numeric_limits<double>::quiet_NaN(), *synchronized));
}
