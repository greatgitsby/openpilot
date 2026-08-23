import math
import time

import openpilot.cereal.messaging as messaging
from openpilot.common.test import OpenpilotTestCase
from openpilot.common.params import Params
from openpilot.selfdrive.navd import navd
from openpilot.selfdrive.navd.helpers import Coordinate, parse_banner_instructions

METERS_PER_DEGREE = math.radians(1.0) * 6371007.2

DESTINATION = {"latitude": 0.0, "longitude": 300.0 / METERS_PER_DEGREE}

CAPTURED_BANNER = {
  "distanceAlongGeometry": 120.0,
  "primary": {
    "text": "Market Street",
    "type": "turn",
    "modifier": "left",
    "components": [{"text": "Market Street", "type": "text"}],
  },
  "secondary": {"text": "toward Ocean Beach"},
  "sub": {
    "text": "",
    "components": [
      {"type": "lane", "active": False, "directions": ["straight"]},
      {"type": "lane", "active": True, "directions": ["slight left", "left"], "active_direction": "left"},
      {"type": "text", "text": "ignored"},
    ],
  },
}


def coord(meters: float) -> list[float]:
  return [meters / METERS_PER_DEGREE, 0.0]


def banner(distance: float, maneuver_type: str, modifier: str) -> dict:
  return {
    "distanceAlongGeometry": distance,
    "primary": {"text": f"{maneuver_type} {modifier}", "type": maneuver_type, "modifier": modifier},
  }


# straight line east: step 0 spans 0-100 m, step 1 spans 100-300 m, step 2 is the arrival
ROUTE_RESPONSE = {
  "routes": [{
    "legs": [{
      "annotation": {"maxspeed": [{"speed": 50, "unit": "km/h"}] * 10},
      "steps": [
        {
          "distance": 100.0, "duration": 10.0, "duration_typical": 12.0,
          "geometry": {"coordinates": [coord(0), coord(100)]},
          "bannerInstructions": [banner(100.0, "turn", "left")],
        },
        {
          "distance": 200.0, "duration": 20.0, "duration_typical": 24.0,
          "geometry": {"coordinates": [coord(100), coord(300)]},
          "bannerInstructions": [banner(200.0, "turn", "right")],
        },
        {
          "distance": 0.0, "duration": 0.0, "duration_typical": 0.0,
          "geometry": {"coordinates": [coord(300), coord(300)]},
          "bannerInstructions": [],
        },
      ],
    }],
  }],
}


class FakeResponse:
  status_code = 200
  text = ""

  def json(self):
    return ROUTE_RESPONSE

  def raise_for_status(self):
    pass


class FakeSubMaster:
  def __init__(self):
    self.updated = {"managerState": False, "gpsLocation": False, "gpsLocationExternal": False}
    self.alive = dict.fromkeys(self.updated, True)
    self.data = {}

  def update(self, timeout=0):
    pass

  def __getitem__(self, key):
    return self.data[key]


class FakePubMaster:
  def __init__(self):
    self.sent = {}

  def send(self, name, msg):
    self.sent.setdefault(name, []).append(msg)


def wait_for_param(key: str, timeout: float = 5.0):
  params = Params()
  end = time.monotonic() + timeout
  while time.monotonic() < end:
    value = params.get(key)
    if value is not None:
      return value
    time.sleep(0.01)
  return None


def position(meters: float) -> Coordinate:
  return Coordinate(0.0, meters / METERS_PER_DEGREE)


class TestNavd(OpenpilotTestCase):
  def setup_method(self):
    self.params = Params()
    self.params.put("MapboxToken", "pk.test")
    self.params.put("NavDestination", DESTINATION)

    self.sm = FakeSubMaster()
    self.pm = FakePubMaster()
    self.route_engine = navd.RouteEngine(self.sm, self.pm)

    service = self.route_engine.gps_location_service
    self.sm.data[service] = getattr(messaging.new_message(service), service)

  def load_route(self, mocker):
    mocker.patch.object(navd.requests, "get", return_value=FakeResponse())
    self.route_engine.last_position = position(0)
    self.route_engine.calculate_route(Coordinate(DESTINATION["latitude"], DESTINATION["longitude"]))

  def last_instruction(self):
    return self.pm.sent["navInstruction"][-1].navInstruction

  def test_route_loaded(self, mocker):
    self.load_route(mocker)
    assert self.route_engine.step_idx == 0
    assert len(self.route_engine.route) == 3
    coords = self.pm.sent["navRoute"][-1].navRoute.coordinates
    assert len(coords) == 6

  def test_maneuver_distance_monotonic(self, mocker):
    self.load_route(mocker)

    distances = []
    for meters in range(0, 100, 10):
      self.route_engine.last_position = position(meters)
      self.route_engine.send_instruction()
      distances.append(self.last_instruction().maneuverDistance)

    assert distances == sorted(distances, reverse=True)
    assert distances[0] == 100.0
    assert self.route_engine.step_idx == 0

  def test_step_advances_after_threshold(self, mocker):
    self.load_route(mocker)

    self.route_engine.last_position = position(109)
    self.route_engine.send_instruction()
    assert self.route_engine.step_idx == 0

    self.route_engine.last_position = position(111)
    self.route_engine.send_instruction()
    assert self.route_engine.step_idx == 1

  def test_remaining_distance_and_time(self, mocker):
    self.load_route(mocker)

    self.route_engine.last_position = position(0)
    self.route_engine.send_instruction()
    instruction = self.last_instruction()
    assert instruction.distanceRemaining == 300.0
    assert instruction.timeRemaining == 30.0
    assert instruction.timeRemainingTypical == 36.0

    self.route_engine.last_position = position(50)
    self.route_engine.send_instruction()
    instruction = self.last_instruction()
    assert instruction.distanceRemaining == 250.0
    assert instruction.timeRemaining == 25.0

  def test_reroute_debounce(self, mocker):
    self.load_route(mocker)

    # 100 m off the route
    self.route_engine.last_position = Coordinate(100.0 / METERS_PER_DEGREE, 0.0)
    for _ in range(navd.REROUTE_COUNTER_MIN):
      assert not self.route_engine.should_recompute()
    assert self.route_engine.should_recompute()

    # back on the route resets the counter
    self.route_engine.last_position = position(50)
    assert not self.route_engine.should_recompute()
    assert self.route_engine.reroute_counter == 0

  def test_destination_reached_clears_param(self, mocker):
    self.load_route(mocker)

    self.route_engine.step_idx = len(self.route_engine.route) - 1
    self.route_engine.last_position = position(400)
    self.route_engine.send_instruction()

    assert self.params.get("NavDestination") is None
    assert self.route_engine.step_idx is None

  def test_idle_without_token(self, mocker):
    self.params.remove("MapboxToken")
    get = mocker.patch.object(navd.requests, "get", return_value=FakeResponse())

    self.route_engine.last_position = position(0)
    self.route_engine.update()

    assert get.call_count == 0
    assert self.route_engine.route is None

  def test_position_from_gps(self):
    service = self.route_engine.gps_location_service
    msg = messaging.new_message(service)
    gps = getattr(msg, service)
    gps.hasFix = True
    gps.horizontalAccuracy = 10.0
    gps.latitude = 32.7427228
    gps.longitude = -117.2321177
    gps.speed = 10.0
    gps.bearingDeg = 42.0

    self.sm.data[service] = gps
    self.sm.updated[service] = True
    self.route_engine.update_location()

    assert self.route_engine.gps_ok
    assert self.route_engine.last_position == Coordinate(32.7427228, -117.2321177)
    assert self.route_engine.last_bearing == 42.0
    assert wait_for_param("LastGPSPosition") is not None

    # inaccurate fix is ignored
    gps.horizontalAccuracy = 100.0
    self.route_engine.update_location()
    assert not self.route_engine.gps_ok
    assert self.route_engine.last_position == Coordinate(32.7427228, -117.2321177)

    # bearing is only trusted above the speed threshold
    gps.horizontalAccuracy = 10.0
    gps.speed = 1.0
    gps.bearingDeg = 180.0
    self.route_engine.update_location()
    assert self.route_engine.last_bearing == 42.0

  def test_parse_banner_instructions(self):
    instruction = parse_banner_instructions([CAPTURED_BANNER], 50.0)
    assert instruction["maneuverPrimaryText"] == "Market Street"
    assert instruction["maneuverType"] == "turn"
    assert instruction["maneuverModifier"] == "left"
    assert instruction["maneuverSecondaryText"] == "toward Ocean Beach"
    assert instruction["showFull"]
    assert instruction["lanes"] == [
      {"active": False, "directions": ["straight"]},
      {"active": True, "directions": ["slightLeft", "left"], "activeDirection": "left"},
    ]

    assert not parse_banner_instructions([CAPTURED_BANNER], 500.0)["showFull"]
    assert parse_banner_instructions([]) is None
