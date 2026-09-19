import itertools
import unittest
from unittest.mock import Mock, patch

from openpilot.selfdrive.modeld import gemmad


class TestGemmad(unittest.TestCase):
  def test_all_five_second_plans(self):
    directions = dict(enumerate(gemmad.DIRECTIONS))
    for slots in itertools.product(directions, repeat=5):
      plan = gemmad.format_plan(list(slots), directions)
      self.assertEqual(sum(part["seconds"] for part in plan), 5)
      self.assertEqual([part["command"] for part in plan for _ in range(part["seconds"])],
                       [directions[token] for token in slots])
      self.assertTrue(all(a["command"] != b["command"] for a, b in zip(plan, plan[1:], strict=False)))

  def test_invalid_plan(self):
    directions = dict(enumerate(gemmad.DIRECTIONS))
    for slots in ([], [0]*4, [0]*6, [0, 0, 0, 0, 99]):
      with self.assertRaises(ValueError):
        gemmad.format_plan(slots, directions)

  def test_waits_for_wide_camera(self):
    client = Mock()
    client.connect.side_effect = [False, True]
    wide = gemmad.VisionStreamType.VISION_STREAM_WIDE_ROAD
    narrow = gemmad.VisionStreamType.VISION_STREAM_NARROW_ROAD
    with patch.object(gemmad, "VisionIpcClient", return_value=client) as ipc, patch.object(gemmad.time, "sleep") as sleep:
      ipc.available_streams.side_effect = [{narrow}, {narrow, wide}]
      self.assertIs(gemmad.connect_road_camera(), client)
      ipc.assert_called_once_with("camerad", wide, True)
      self.assertEqual(sleep.call_count, 2)


if __name__ == "__main__":
  unittest.main()
