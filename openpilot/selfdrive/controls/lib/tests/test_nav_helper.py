import openpilot.cereal.messaging as messaging
from openpilot.cereal import log
from openpilot.common.params import Params
from openpilot.common.realtime import DT_MDL
from openpilot.common.test import OpenpilotTestCase
from openpilot.selfdrive.controls.lib import nav_helper
from openpilot.selfdrive.controls.lib.nav_helper import NavHelper, maneuver_desire

Desire = log.Desire
LaneChangeState = log.LaneChangeState
NavLaneAdvice = log.ModelDataV2.NavLaneAdvice


class FakeDesireHelper:
  def __init__(self):
    self.lane_change_state = LaneChangeState.off
    self.desire = Desire.none


def make_carstate(v_ego=20., left_blinker=False, right_blinker=False, steering_pressed=False,
                  left_blindspot=False, right_blindspot=False):
  cs = messaging.new_message('carState').carState
  cs.vEgo = v_ego
  cs.leftBlinker = left_blinker
  cs.rightBlinker = right_blinker
  cs.steeringPressed = steering_pressed
  cs.leftBlindspot = left_blindspot
  cs.rightBlindspot = right_blindspot
  return cs


def make_model(left_lane=False, right_lane=False):
  # road edge at 10 m means there is room for an adjacent lane, 2 m means there is not
  model = messaging.new_message('modelV2').modelV2
  model.laneLineProbs = [1. if left_lane else 0., 1., 1., 1. if right_lane else 0.]
  edges = model.init('roadEdges', 2)
  edges[0].y = [10. if left_lane else 2.]
  edges[1].y = [10. if right_lane else 2.]
  return model


def make_nav(maneuver_type='turn', modifier='left', distance=30.):
  nav = messaging.new_message('navInstruction').navInstruction
  nav.maneuverType = maneuver_type
  nav.maneuverModifier = modifier
  nav.maneuverDistance = distance
  return nav


class TestNavHelper(OpenpilotTestCase):
  def setUp(self):
    super().setUp()
    self.DH = FakeDesireHelper()
    self.desire_enabled = True

  def helper(self, auto=False):
    NH = NavHelper(Params(), bsm_available=auto)
    NH.desire_enabled = self.desire_enabled
    NH.auto_lane_change = auto
    return NH

  def step(self, NH, nav, carstate=None, model=None, lateral_active=True, n=1, nav_valid=True):
    carstate = carstate if carstate is not None else make_carstate()
    model = model if model is not None else make_model()
    for _ in range(n):
      NH.update(carstate, model, nav, nav_valid, lateral_active, self.DH)
    return NH.desire

  def test_maneuver_mapping(self):
    cases = [
      ('turn', 'left', Desire.turnLeft),
      ('turn', 'right', Desire.turnRight),
      ('turn', 'sharp left', Desire.turnLeft),
      ('turn', 'sharp right', Desire.turnRight),
      ('end of road', 'left', Desire.turnLeft),
      ('continue', 'right', Desire.turnRight),
      ('new name', 'left', Desire.turnLeft),
      ('turn', 'slight left', Desire.keepLeft),
      ('turn', 'slight right', Desire.keepRight),
      ('fork', 'left', Desire.keepLeft),
      ('off ramp', 'right', Desire.keepRight),
      ('on ramp', 'right', Desire.keepRight),
      ('merge', 'left', Desire.keepLeft),
      ('uturn', 'uturn', Desire.none),
      ('roundabout', 'left', Desire.none),
      ('rotary', 'right', Desire.none),
      ('arrive', 'left', Desire.none),
      ('depart', 'right', Desire.none),
      ('turn', 'straight', Desire.none),
      ('turn', '', Desire.none),
    ]
    for maneuver_type, modifier, expected in cases:
      with self.subTest(maneuver_type=maneuver_type, modifier=modifier):
        self.assertEqual(maneuver_desire(maneuver_type, modifier), expected)

  def test_windows_and_speed_gates(self):
    cases = [
      # type, modifier, distance, v_ego, expected
      ('turn', 'left', 30., 10., Desire.turnLeft),
      ('turn', 'left', 5., 10., Desire.none),      # too close
      ('turn', 'left', 100., 10., Desire.none),    # too far
      ('turn', 'left', 30., 20., Desire.none),     # too fast for a turn
      ('turn', 'left', 44., 14., Desire.turnLeft),
      ('off ramp', 'right', 50., 25., Desire.keepRight),
      ('off ramp', 'right', 50., 5., Desire.none), # too slow for a keep
      ('off ramp', 'right', 200., 25., Desire.none),
    ]
    for maneuver_type, modifier, distance, v_ego, expected in cases:
      with self.subTest(maneuver_type=maneuver_type, distance=distance, v_ego=v_ego):
        NH = self.helper()
        desire = self.step(NH, make_nav(maneuver_type, modifier, distance), make_carstate(v_ego=v_ego))
        self.assertEqual(desire, expected)

  def test_desire_gated_by_param(self):
    self.desire_enabled = False
    NH = self.helper()
    self.assertEqual(self.step(NH, make_nav('turn', 'left', 30.), make_carstate(v_ego=10.)), Desire.none)

  def test_one_pulse_per_maneuver(self):
    NH = self.helper()
    cs = make_carstate(v_ego=10.)
    nav = make_nav('turn', 'left', 30.)
    self.assertEqual(self.step(NH, nav, cs), Desire.turnLeft)

    # leaving the window latches the maneuver off
    self.assertEqual(self.step(NH, make_nav('turn', 'left', 8.), cs), Desire.none)
    self.assertEqual(self.step(NH, make_nav('turn', 'left', 20.), cs), Desire.none)

    # a new maneuver pulses again
    self.assertEqual(self.step(NH, make_nav('turn', 'right', 30.), cs), Desire.turnRight)

  def test_blinker_and_lateral_precedence(self):
    nav = make_nav('turn', 'left', 30.)
    cs = make_carstate(v_ego=10.)
    self.assertEqual(self.step(self.helper(), nav, cs, lateral_active=False), Desire.none)
    self.assertEqual(self.step(self.helper(), nav, make_carstate(v_ego=10., left_blinker=True)), Desire.none)

    NH = self.helper()
    self.DH.lane_change_state = LaneChangeState.preLaneChange
    self.assertEqual(self.step(NH, nav, cs), Desire.none)

  def test_no_advice_between_maneuvers(self):
    NH = self.helper()
    self.step(NH, make_nav('turn', 'left', 5000.), make_carstate(v_ego=25.), make_model(left_lane=True, right_lane=True))
    self.assertEqual(NH.lane_advice, NavLaneAdvice.none)

  def test_exit_approach_advice(self):
    NH = self.helper()
    self.step(NH, make_nav('off ramp', 'right', 700.), make_carstate(v_ego=25.), make_model(right_lane=True))
    self.assertEqual(NH.lane_advice, NavLaneAdvice.moveRight)

    # no advice once the road edge is one lane width away on the maneuver side
    NH = self.helper()
    self.step(NH, make_nav('off ramp', 'right', 700.), make_carstate(v_ego=25.), make_model())
    self.assertEqual(NH.lane_advice, NavLaneAdvice.none)

  def test_in_town_turn_advice(self):
    NH = self.helper()
    self.step(NH, make_nav('turn', 'left', 400.), make_carstate(v_ego=10.), make_model(left_lane=True))
    self.assertEqual(NH.lane_advice, NavLaneAdvice.moveLeft)

  def test_on_ramp_advice_away_from_merge(self):
    NH = self.helper()
    cs = make_carstate(v_ego=25.)
    model = make_model(left_lane=True)
    self.step(NH, make_nav('on ramp', 'slight right', 100.), cs, model)
    self.assertEqual(NH.lane_advice, NavLaneAdvice.none)

    # the on ramp step completed, move away from the merge side
    self.step(NH, make_nav('continue', 'straight', 3000.), cs, model)
    self.assertEqual(NH.lane_advice, NavLaneAdvice.moveLeft)

    # advice expires after the merge window
    self.step(NH, make_nav('continue', 'straight', 3000.), cs, model, n=int(nav_helper.MERGE_ADVICE_TIME / DT_MDL))
    self.assertEqual(NH.lane_advice, NavLaneAdvice.none)

  def test_auto_lane_change(self):
    NH = self.helper(auto=True)
    nav = make_nav('off ramp', 'right', 700.)
    cs = make_carstate(v_ego=25.)
    model = make_model(right_lane=True)
    self.assertEqual(self.step(NH, nav, cs, model), Desire.laneChangeRight)
    self.assertTrue(NH.lane_advice_auto)

    # debounced after a change
    self.assertEqual(self.step(NH, nav, cs, model), Desire.none)
    self.assertEqual(NH.lane_advice, NavLaneAdvice.moveRight)

  def test_auto_requires_bsm_and_param(self):
    NH = self.helper()
    desire = self.step(NH, make_nav('off ramp', 'right', 700.), make_carstate(v_ego=25.), make_model(right_lane=True))
    self.assertEqual(desire, Desire.none)

  def test_lane_checks(self):
    NH = self.helper(auto=True)
    model = make_model(right_lane=True)
    cases = [
      ('missing adjacent lane', make_carstate(v_ego=25.), make_model(), False),
      ('blindspot', make_carstate(v_ego=25., right_blindspot=True), model, False),
      ('too slow', make_carstate(v_ego=2.), model, False),
      ('steering override', make_carstate(v_ego=25., steering_pressed=True), model, False),
      ('ok', make_carstate(v_ego=25.), model, True),
    ]
    for label, cs, m, expected in cases:
      with self.subTest(label):
        self.assertEqual(NH.lane_change_ok(m, cs, 'right'), expected)

  def test_lane_check_debounce_and_consecutive_cap(self):
    NH = self.helper(auto=True)
    cs = make_carstate(v_ego=25.)
    model = make_model(right_lane=True)
    NH.t = 100.
    NH._count_change('right')
    self.assertFalse(NH.lane_change_ok(model, cs, 'right'))
    NH.t += nav_helper.LANE_CHANGE_DEBOUNCE + 1.
    self.assertTrue(NH.lane_change_ok(model, cs, 'right'))

    for _ in range(nav_helper.MAX_CONSECUTIVE_CHANGES):
      NH.t += nav_helper.LANE_CHANGE_DEBOUNCE + 1.
      NH._count_change('right')
    NH.t += nav_helper.LANE_CHANGE_DEBOUNCE + 1.
    self.assertFalse(NH.lane_change_ok(model, cs, 'right'))
    self.assertTrue(NH.lane_change_ok(make_model(left_lane=True), cs, 'left'))

  def test_invalid_nav(self):
    NH = self.helper()
    desire = self.step(NH, make_nav('turn', 'left', 30.), make_carstate(v_ego=10.), nav_valid=False)
    self.assertEqual(desire, Desire.none)
    self.assertEqual(NH.lane_advice, NavLaneAdvice.none)
