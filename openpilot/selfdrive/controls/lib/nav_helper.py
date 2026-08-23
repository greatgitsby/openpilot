from openpilot.cereal import log
from openpilot.common.params import Params
from openpilot.common.realtime import DT_MDL
from openpilot.selfdrive.controls.lib.desire_helper import LANE_CHANGE_SPEED_MIN

Desire = log.Desire
LaneChangeState = log.LaneChangeState
NavLaneAdvice = log.ModelDataV2.NavLaneAdvice

# maneuver types
TURN_TYPES = {'turn', 'end of road', 'continue', 'new name'}
KEEP_TYPES = {'fork', 'off ramp', 'on ramp', 'merge'}
MERGE_TYPES = {'on ramp', 'merge'}
EXIT_TYPES = {'off ramp', 'fork'}

MODIFIER_SIDE = {
  'left': 'left',
  'sharp left': 'left',
  'slight left': 'left',
  'right': 'right',
  'sharp right': 'right',
  'slight right': 'right',
}

# desire windows
TURN_DIST_MIN = 10.
TURN_DIST_MIN_MAX = 45.
TURN_DIST_T = 2.
TURN_SPEED_MAX = 15.
KEEP_DIST_MIN_MAX = 60.
KEEP_DIST_T = 3.
KEEP_SPEED_MIN = 8.
# a maneuver is considered new when its distance grows by this much
MANEUVER_RESET_DIST = 20.

# lane positioning
ADVICE_DIST_MIN_MAX = 800.
ADVICE_DIST_T = 60.
MERGE_ADVICE_TIME = 20.
LANE_WIDTH = 3.7
LANE_PROB_MIN = 0.5
LANE_CHANGE_DEBOUNCE = 15.
MAX_CONSECUTIVE_CHANGES = 3

TURN_DESIRE = {'left': Desire.turnLeft, 'right': Desire.turnRight}
KEEP_DESIRE = {'left': Desire.keepLeft, 'right': Desire.keepRight}
LANE_CHANGE_DESIRE = {'left': Desire.laneChangeLeft, 'right': Desire.laneChangeRight}
ADVICE = {'left': NavLaneAdvice.moveLeft, 'right': NavLaneAdvice.moveRight}
OPPOSITE = {'left': 'right', 'right': 'left'}


def maneuver_desire(maneuver_type: str, modifier: str) -> int:
  side = MODIFIER_SIDE.get(modifier)
  if side is None:
    return Desire.none
  if maneuver_type in KEEP_TYPES or modifier.startswith('slight'):
    return KEEP_DESIRE[side]
  if maneuver_type in TURN_TYPES:
    return TURN_DESIRE[side]
  return Desire.none


class NavHelper:
  def __init__(self, params: Params | None = None, bsm_available: bool = False):
    params = params if params is not None else Params()
    self.desire_enabled = params.get_bool("NavDesireEnabled")
    self.auto_lane_change = params.get_bool("NavAutoLaneChange") and bsm_available

    self.desire = Desire.none
    self.lane_advice = NavLaneAdvice.none
    self.lane_advice_auto = False

    self.t = 0.
    self.maneuver_key: tuple[str, str] | None = None
    self.prev_distance = 0.
    self.desire_latched = False
    self.desire_active = False

    self.merge_side: str | None = None
    self.merge_done_t = -1e9
    self.last_change_t = -1e9
    self.consecutive_dir: str | None = None
    self.consecutive_count = 0
    self.prev_lane_change_state = LaneChangeState.off

  def _track_maneuver(self, maneuver_type: str, modifier: str, distance: float) -> None:
    key = (maneuver_type, modifier)
    if key != self.maneuver_key or distance > self.prev_distance + MANEUVER_RESET_DIST:
      if self.maneuver_key is not None and self.maneuver_key[0] in MERGE_TYPES:
        side = MODIFIER_SIDE.get(self.maneuver_key[1])
        if side is not None:
          self.merge_side = side
          self.merge_done_t = self.t
      self.maneuver_key = key
      self.desire_latched = False
      self.desire_active = False
    self.prev_distance = distance

  def _in_window(self, desire: int, distance: float, v_ego: float) -> bool:
    if desire in (Desire.turnLeft, Desire.turnRight):
      return TURN_DIST_MIN < distance < max(TURN_DIST_MIN_MAX, TURN_DIST_T * v_ego) and v_ego < TURN_SPEED_MAX
    if desire in (Desire.keepLeft, Desire.keepRight):
      return 0. < distance < max(KEEP_DIST_MIN_MAX, KEEP_DIST_T * v_ego) and v_ego > KEEP_SPEED_MIN
    return False

  @staticmethod
  def lane_exists(model_v2, side: str) -> bool:
    probs = model_v2.laneLineProbs
    edges = model_v2.roadEdges
    if len(probs) < 4 or len(edges) < 2:
      return False
    prob = probs[0] if side == 'left' else probs[3]
    edge = edges[0] if side == 'left' else edges[1]
    if len(edge.y) == 0:
      return False
    return prob > LANE_PROB_MIN and abs(edge.y[0]) > LANE_WIDTH

  def lane_change_ok(self, model_v2, carstate, side: str) -> bool:
    if not self.lane_exists(model_v2, side):
      return False
    if carstate.vEgo < LANE_CHANGE_SPEED_MIN:
      return False
    if (carstate.leftBlindspot if side == 'left' else carstate.rightBlindspot):
      return False
    if carstate.leftBlinker or carstate.rightBlinker or carstate.steeringPressed:
      return False
    if self.t - self.last_change_t < LANE_CHANGE_DEBOUNCE:
      return False
    if self.consecutive_dir == side and self.consecutive_count >= MAX_CONSECUTIVE_CHANGES:
      return False
    return True

  def _advice_side(self, model_v2, maneuver_type: str, modifier: str, distance: float, v_ego: float) -> str | None:
    if self.merge_side is not None and self.t - self.merge_done_t < MERGE_ADVICE_TIME:
      side = OPPOSITE[self.merge_side]
      if self.lane_exists(model_v2, side):
        return side
      return None

    if maneuver_type not in EXIT_TYPES and maneuver_type not in TURN_TYPES:
      return None
    side = MODIFIER_SIDE.get(modifier)
    if side is None:
      return None
    if distance > max(ADVICE_DIST_MIN_MAX, ADVICE_DIST_T * v_ego):
      return None
    # already in the outermost lane on the maneuver side
    if not self.lane_exists(model_v2, side):
      return None
    return side

  def _count_change(self, side: str) -> None:
    self.last_change_t = self.t
    if self.consecutive_dir == side:
      self.consecutive_count += 1
    else:
      self.consecutive_dir = side
      self.consecutive_count = 1

  def update(self, carstate, model_v2, nav_instruction, nav_valid: bool, lateral_active: bool, desire_helper) -> None:
    self.t += DT_MDL
    self.desire = Desire.none
    self.lane_advice = NavLaneAdvice.none
    self.lane_advice_auto = False

    if desire_helper.lane_change_state == LaneChangeState.laneChangeStarting and \
       self.prev_lane_change_state != LaneChangeState.laneChangeStarting:
      self._count_change('left' if desire_helper.desire == Desire.laneChangeLeft else 'right')
    self.prev_lane_change_state = desire_helper.lane_change_state

    if not nav_valid:
      self.maneuver_key = None
      self.merge_side = None
      return

    maneuver_type = nav_instruction.maneuverType.lower()
    modifier = nav_instruction.maneuverModifier.lower()
    distance = nav_instruction.maneuverDistance
    v_ego = carstate.vEgo

    self._track_maneuver(maneuver_type, modifier, distance)

    # driver blinker lane change always wins
    blocked = not lateral_active or carstate.leftBlinker or carstate.rightBlinker or \
              desire_helper.lane_change_state != LaneChangeState.off

    side = self._advice_side(model_v2, maneuver_type, modifier, distance, v_ego)
    if side is not None and not blocked:
      self.lane_advice = ADVICE[side]
      if self.auto_lane_change and self.desire_enabled and self.lane_change_ok(model_v2, carstate, side):
        self.lane_advice_auto = True
        self.desire = LANE_CHANGE_DESIRE[side]
        self._count_change(side)
        return

    desire = maneuver_desire(maneuver_type, modifier)
    in_window = desire != Desire.none and self._in_window(desire, distance, v_ego)
    if self.desire_active and not in_window:
      self.desire_latched = True
    self.desire_active = in_window

    if in_window and not self.desire_latched and self.desire_enabled and not blocked:
      self.desire = desire
