"""Sustained and seek-heavy HD camera playback under Xvfb."""

import os
from pathlib import Path
import time

import pytest

from openpilot.tools.cabana.tests.analysis_fixture import generate, add_cameras
from openpilot.tools.cabana.tests.test_analysis_ui import App, BINARY

pytestmark = pytest.mark.skipif(os.environ.get('CABANA_E2E') != '1', reason='Set CABANA_E2E=1 for Xvfb tests')


@pytest.fixture(scope='module')
def preset_data(tmp_path_factory):
  existing = os.environ.get('CABANA_PRESET_FIXTURE')
  if existing:
    return Path(existing)
  directory = tmp_path_factory.mktemp('preset-data')
  generate(directory, 6000)
  add_cameras(directory, 6000, resolution='1920x1080', b_frames=False)
  return directory


def seek_fraction(app, fraction):
  x1, y1, x2, y2 = app.state()['items']['Timeline'][0]
  app.x('mousemove', int(x1 + (x2 - x1) * fraction), int((y1 + y2) / 2))
  app.x('mousedown', 1)
  time.sleep(0.04)
  app.x('mouseup', 1)


def test_hd_camera_playback_and_cached_seeks(tmp_path, preset_data):
  app = App(tmp_path, layout=str(BINARY.parent / 'layouts/cameras-and-map.json'), prepared=preset_data)
  names = ['road camera', 'wide_road camera', 'driver camera']

  def caught_up(state):
    return all(abs(state.get('plots', {}).get(name, {}).get('frame', -100) - int(state['cursor'] * 20)) <= 1 for name in names)

  try:
    app.wait(caught_up, timeout=30)
    latencies = []
    for fraction in [0.9, 0.1, 0.75, 0.25, 0.9, 0.1, 0.75, 0.25]:
      start = time.monotonic()
      seek_fraction(app, fraction)
      app.wait(caught_up, timeout=2)
      latencies.append(time.monotonic() - start)
    assert max(latencies) < 0.75, latencies
    seek_fraction(app, 0.5)
    app.wait(caught_up, timeout=2)
    app.click('Speed')
    app.x('keydown', 'ctrl')
    app.click('Speed')
    app.x('keyup', 'ctrl')
    app.x('key', 'ctrl+a')
    app.x('type', '4')
    app.x('key', 'Return')
    app.click('Play')
    updates = {name: set() for name in names}
    lag = []
    start = time.monotonic()
    while time.monotonic() - start < 4:
      state = app.state()
      for name in names:
        frame = state['plots'][name]['frame']
        updates[name].add(frame)
        lag.append(state['cursor'] - frame / 20)
      time.sleep(0.025)
    assert min(map(len, updates.values())) >= 50, updates
    assert max(lag) < 0.75, max(lag)
    print('HD seek seconds:', latencies, 'updates:', {name: len(frames) for name, frames in updates.items()}, 'max lag:', max(lag))
  finally:
    app.close()
