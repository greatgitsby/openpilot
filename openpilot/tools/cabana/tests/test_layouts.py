import json
import math
import subprocess
from pathlib import Path

from openpilot.common.parameterized import parameterized
from openpilot.common.test import OpenpilotTestCase
from openpilot.tools.cabana.analysis.cabana_equations import compile_numeric_equation

LAYOUTS = Path(__file__).resolve().parents[1] / "layouts"


def load_layout(name):
  return json.loads((LAYOUTS / name).read_text())


def load_equations(name):
  return {e["name"]: e for e in load_layout(name).get("equations", [])}


def compile_equation(e, input_count):
  return compile_numeric_equation(e.get("globals", ""), e["function"], input_count)


class TestLayouts(OpenpilotTestCase):
  @parameterized.expand(sorted(LAYOUTS.glob("*.json")), ids=lambda p: p.stem)
  def test_bundled_layouts(self, path):
    assert json.loads(path.read_text())["cabana_layout"] == 4
    result = subprocess.run([str(Path(__file__).with_name("test_cabana")), "--check-layout", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

  def test_tuning_equations(self):
    yaw = load_equations("tuning.json")["engaged curvature yaw"]
    assert yaw["source"] == "/carControl/angularVelocity/2"
    assert yaw["additional"] == ["/carState/steeringPressed", "/carControl/enabled", "/carState/vEgo"]
    assert "global last_bad_time" in yaw["function"]
    assert "engage_delay = 5" in yaw["globals"]

  def test_limits_and_scaling(self):
    chart = load_layout("camera-timings.json")["charts"][0]
    assert (chart["y_min"], chart["y_max"]) == (3.5e7, 6.5e7)
    speed = [s for c in load_layout("max-torque-debug.json")["charts"] for s in c["signals"] if isinstance(s, dict)]
    assert speed == [{"path": "/carState/vEgo", "scale": 2.23694}]

  def test_python_ports_numeric_results(self):
    cases = {
      "haversine distance [m]": (0, [0, 0, 90], 10018754.171394622),
      "roll compensated lateral acceleration": (5, [3, 0.2, 0, 1], 43.038),
      "Desired lateral accel (roll compensated)": (5, [3, 0.2], 43.038),
      "Actual lateral accel (roll compensated)": (5, [3, 0.2], 43.038),
      "carState.vEgo kmh": (5, [], 18),
      "carState.vEgo mph": (5, [], 11.1847),
      "engaged curvature yaw": (5, [0, 1, 10], 0.5),
      "engaged curvature vehicle model": (5, [0, 1], 5),
      "engaged curvature plan": (5, [0, 1], 5),
      "engaged_accel_actual": (5, [0, 0, 1], 5),
      "engaged_accel_plan": (5, [0, 0, 1], 5),
      "engaged_accel_actuator": (5, [0, 0, 1], 5),
      "steering rate limited": (5, [5, 1, 1], 0),
    }
    for path in LAYOUTS.glob("*.json"):
      for name, e in load_equations(path.name).items():
        value, additional, expected = cases[name]
        calc = compile_equation(e, len(additional))
        assert math.isclose(calc(100.0, float(value), *map(float, additional)), expected, rel_tol=1e-6, abs_tol=1e-12), name

  def test_python_tuning_gates_and_zero_speed(self):
    equations = load_equations("tuning.json")
    for brake, gas, enabled in [(1, 0, 1), (0, 1, 1), (0, 0, 0)]:
      calc = compile_equation(equations["engaged_accel_actual"], 3)
      assert calc(100, 5, brake, gas, enabled) == 0
      assert calc(105, 5, 0, 0, 1) == 0
      assert calc(105.01, 5, 0, 0, 1) == 5
    calc = compile_equation(equations["engaged curvature yaw"], 3)
    assert math.isnan(calc(100, 0.02, 0, 1, 0))
    assert math.isclose(calc(101, 0.02, 0, 1, 20), 0.001, rel_tol=1e-6, abs_tol=1e-12)
