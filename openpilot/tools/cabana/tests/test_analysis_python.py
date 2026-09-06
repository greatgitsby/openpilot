from pathlib import Path

import pytest

from openpilot.tools.cabana.analysis.evaluate import evaluate
from openpilot.tools.cabana.analysis.import_layout import import_xml


def request(code, **kwargs):
  return {
    'channels': {'speed': [[0, 1], [1, 2], [2, 4]], 'other': [[0.5, 10], [1.5, 20]]},
    'formula': {'linked_source': 'speed', 'function_code': code, **kwargs},
  }


def test_numpy_formulas():
  assert evaluate(request('return value * 3.6')) == [[0, 3.6], [1, 7.2], [2, 14.4]]
  assert evaluate(request('42')) == [[0, 42], [1, 42], [2, 42]]
  assert evaluate(request('return v1', additional_sources=['other'])) == [[1, 10], [2, 20]]
  assert evaluate(request('return (time[::-1], value[::-1])')) == [[0, 1], [1, 2], [2, 4]]
  assert evaluate(request('return value * multiplier', globals_code='multiplier = 2'))[-1] == [2, 8]
  assert evaluate(request('return v("speed") + 1'))[-1] == [2, 5]


@pytest.mark.parametrize('code', ['return []', 'return np.zeros((3, 2))', 'return np.nan', 'raise ValueError("bad")', 'return missing_name', 'return ([], [])'])
def test_invalid_formulas(code):
  with pytest.raises((ValueError, NameError)):
    evaluate(request(code))


def test_all_presets_import():
  directory = Path(__file__).resolve().parents[2] / 'plotjuggler/layouts'
  for source in directory.glob('*.xml'):
    layout = import_xml(source)
    assert layout['tabs']
    for formula in layout['formulas']:
      compile(formula['globals_code'], source.name, 'exec')
      compile('def formula():\n' + '\n'.join('  ' + line for line in formula['function_code'].splitlines()), source.name, 'exec')


def test_map_cache_and_bounds(tmp_path):
  import hashlib
  import json
  from openpilot.tools.cabana.analysis.map_data import roads

  bounds = [33.45, -112.07, 33.46, -112.06]
  cached = {'roads': [[[-112.07, 33.45], [-112.06, 33.46]]]}
  target = tmp_path / (hashlib.sha256(json.dumps(bounds).encode()).hexdigest() + '.json')
  target.write_text(json.dumps(cached))
  assert roads({'bounds': bounds, 'cache': str(tmp_path)}) == cached
  with pytest.raises(ValueError):
    roads({'bounds': [-90, -180, 90, 180], 'cache': str(tmp_path)})
