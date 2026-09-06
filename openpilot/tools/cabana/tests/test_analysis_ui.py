"""Input-driven Xvfb tests. Run with CABANA_E2E=1 pytest -q -s this_file."""

import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import time
import uuid

import pytest
from PIL import Image

from openpilot.tools.cabana.tests.analysis_fixture import generate, add_cameras

pytestmark = pytest.mark.skipif(os.environ.get('CABANA_E2E') != '1', reason='Set CABANA_E2E=1 to run Xvfb integration tests')
BINARY = Path(__file__).resolve().parents[1] / 'cabana'


class App:
  def __init__(self, directory, count=1000, layout='layout.json', live=False, remote=False, route=None, prepared=None):
    self.directory = directory
    if prepared is None:
      generate(directory, count)
      if layout == "cameras.json":
        add_cameras(directory, count)
    else:
      for source in prepared.iterdir():
        if source.is_file():
          (directory / source.name).symlink_to(source)

    self.xvfb = subprocess.Popen(['Xvfb', '-displayfd', '1', '-screen', '0', '1600x1000x24'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    display = ':' + self.xvfb.stdout.readline().strip()
    self.env = dict(os.environ, DISPLAY=display, XDG_CONFIG_HOME=str(directory / 'config'), LIBGL_ALWAYS_SOFTWARE='1')
    self.env.pop('WAYLAND_DISPLAY', None)
    self.publisher = None
    self.outbound_bridge = None
    self.publisher_prefix = None
    if live:
      self.env['OPENPILOT_PREFIX'] = 'cabana-test-' + uuid.uuid4().hex[:12]
      Path('/dev/shm/msgq_' + self.env['OPENPILOT_PREFIX']).mkdir()
      publisher_env = self.env.copy()
      if remote:
        self.publisher_prefix = self.env['OPENPILOT_PREFIX'] + '-publisher'
        publisher_env['OPENPILOT_PREFIX'] = self.publisher_prefix
        Path('/dev/shm/msgq_' + self.publisher_prefix).mkdir()
        self.outbound_bridge = subprocess.Popen(
          [str(BINARY.parents[2] / 'cereal/messaging/bridge')], env=publisher_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
      self.publisher = subprocess.Popen(
        [os.sys.executable, str(Path(__file__).with_name('live_fixture.py'))], env=publisher_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
      )
    self.log = (directory / 'run.log').open('w')
    stream_args = ['--stream', '--buffer-seconds', '1'] if live else [str(directory / 'rlog')]
    if route:
      segment = directory / '2026-09-06--01-00-00--0'
      segment.mkdir()
      shutil.copy(directory / 'rlog', segment / 'rlog')
      shutil.copy(directory / 'rlog', segment / 'qlog')
      stream_args = ['2026-09-06--01-00-00/0/' + route, '--data_dir', str(directory), '--no-vipc']
    if remote:
      stream_args += ['--address', '127.0.0.1']
    self.process = subprocess.Popen(
      [
        str(BINARY),
        *stream_args,
        '--dbc',
        str(directory / 'fixture.dbc'),
        '--layout',
        str(directory / layout),
        '--output',
        str(directory / 'overview.png'),
        '--show',
        '--test-state',
        str(directory / 'state.json'),
      ],
      env=self.env,
      stdout=self.log,
      stderr=subprocess.STDOUT,
    )
    try:
      self.wait(lambda s: s.get('channels', 0) > 0 and ('Play' in s.get('items', {}) or 'Pause' in s.get('items', {})), timeout=60)
    except Exception:
      self.close()
      raise

  def state(self):
    assert self.process.poll() is None, (self.directory / 'run.log').read_text()
    try:
      return json.loads((self.directory / 'state.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
      return {}

  def wait(self, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
      state = self.state()
      if predicate(state):
        return state
      time.sleep(0.05)
    raise AssertionError(f'Timed out; state={self.state()}')

  def x(self, *args):
    subprocess.run(['xdotool', *map(str, args)], env=self.env, check=True, capture_output=True)

  def click(self, label, index=0, twice=False):
    state = self.wait(lambda s: label in s.get('items', {}))
    x1, y1, x2, y2 = state['items'][label][index]
    self.x('mousemove', int((x1 + x2) / 2), int((y1 + y2) / 2))
    time.sleep(0.08)
    for _ in range(2 if twice else 1):
      self.x('mousedown', 1)
      time.sleep(0.04)
      self.x('mouseup', 1)
      time.sleep(0.06)
    time.sleep(0.12)

  def text(self, label, value):
    self.click(label)
    self.x('keydown', 'ctrl')
    time.sleep(0.04)
    self.x('key', '--delay', 50, 'a')
    time.sleep(0.04)
    self.x('keyup', 'ctrl')
    time.sleep(0.08)
    for index, line in enumerate(value.split('\n')):
      if index:
        self.x('key', '--delay', 50, 'Return')
        time.sleep(0.08)
      self.x('type', '--clearmodifiers', '--delay', 1, line)
      time.sleep(0.08)
    self.wait(lambda s: s.get('texts', {}).get(label) == value)
    time.sleep(0.12)

  def close(self):
    if self.process.poll() is None:
      self.process.terminate()
      try:
        self.process.wait(timeout=20)
      except subprocess.TimeoutExpired:
        self.process.kill()
        self.process.wait()
    if self.publisher is not None:
      self.publisher.terminate()
      self.publisher.wait(timeout=5)
      shutil.rmtree('/dev/shm/msgq_' + self.env['OPENPILOT_PREFIX'], ignore_errors=True)
    if self.outbound_bridge is not None:
      self.outbound_bridge.terminate()
      self.outbound_bridge.wait(timeout=5)
      shutil.rmtree('/dev/shm/msgq_' + self.publisher_prefix, ignore_errors=True)
    self.xvfb.terminate()
    self.xvfb.wait(timeout=5)
    self.log.close()


@pytest.fixture
def app(tmp_path):
  instance = App(tmp_path)
  try:
    yield instance
  finally:
    instance.close()


def test_browse_seek_python_and_tabs(app):
  state = app.wait(lambda s: '/carState/vEgo' in s.get('plots', {}))
  assert state['logs'] == 100 and state['thumbnails'] == 10
  assert state['plots']['/carState/vEgo']['count'] == 1000
  assert state['plots']['/carState/vEgo']['last'] == pytest.approx(19.98, abs=1e-5)
  app.click('Step >')
  assert app.state()['cursor'] == pytest.approx(0.1)
  app.text('Search signals', '/carState/steeringAngleDeg')
  app.click('/carState/steeringAngleDeg', twice=True)
  app.wait(lambda s: '/carState/steeringAngleDeg' in s.get('plots', {}))
  app.click('Custom series...')
  app.text('Name', 'speed_kph')
  app.text('Input series', '/carState/vEgo')
  app.text('Formula code', 'return value * 3.6')
  app.click('Preview result')
  app.wait(lambda s: s.get('preview_samples') == 1000)
  app.click('Apply series')
  app.wait(lambda s: s.get('custom_channels') == 1)
  # Deliberately hang the evaluator; the window and timeline must keep responding.
  app.text('Formula code', 'while True:\n  pass')
  app.click('Preview result')
  app.wait(lambda s: 'time limit' in s.get('error', ''), timeout=22)
  assert app.process.poll() is None
  app.text('Formula code', 'return value + 1')
  app.click('Preview result')
  app.wait(lambda s: not s.get('evaluating') and not s.get('error'))
  app.x('key', 'Escape')
  assert app.process.poll() is None
  deadline = time.monotonic() + 10
  while not (app.directory / 'overview.png').exists() and time.monotonic() < deadline:
    time.sleep(0.1)
  image = Image.open(app.directory / 'overview.png')
  assert image.size == (1600, 900)
  assert len(image.getcolors(maxcolors=1_000_000)) > 100


def test_rapid_seek_and_tabs(app):
  random.seed(21)
  rss_before = int(Path(f'/proc/{app.process.pid}/status').read_text().split('VmRSS:')[1].split()[0])
  for i in range(100):
    state = app.state()
    x1, y1, x2, y2 = state['items']['Timeline'][0]
    app.x('mousemove', int(x1 + (x2 - x1) * random.random()), int((y1 + y2) / 2), 'mousedown', 1)
    time.sleep(0.04)
    app.x('mouseup', 1)
    if i % 10 == 0:
      app.click('New tab')
  app.wait(lambda s: len(s['layout']['tabs']) == 12)
  rss_after = int(Path(f'/proc/{app.process.pid}/status').read_text().split('VmRSS:')[1].split()[0])
  assert rss_after - rss_before < 150_000
  assert app.state()['error'] == ''


def test_invalid_layout_recovers(tmp_path):
  app = App(tmp_path, layout='malformed.json')
  try:
    assert 'Load layout' in app.state()['error']
    app.click('Step >')
    assert app.state()['cursor'] == pytest.approx(0.1)
  finally:
    app.close()


def test_live_rollover_and_bad_packets(tmp_path):
  app = App(tmp_path, live=True)
  try:
    state = app.wait(lambda s: s.get('cursor', 0) > 10, timeout=20)
    assert state['data_last'] - state['data_first'] <= 1.001
    assert state['samples'] < 25_000
    app.click('Pause')
    paused = app.state()['cursor']
    time.sleep(0.4)
    assert app.state()['cursor'] == paused
    app.click('Play')
    app.wait(lambda s: s.get('cursor', 0) > paused)
    assert app.process.poll() is None
  finally:
    app.close()


def test_dense_log(tmp_path):
  app = App(tmp_path, count=100_000)
  try:
    state = app.wait(lambda s: s.get('plots', {}).get('/carState/vEgo', {}).get('count') == 100_000, timeout=60)
    assert state['samples'] > 5_000_000
    time.sleep(2)
    assert app.state()['fps'] > 10
    rss = int(Path(f'/proc/{app.process.pid}/status').read_text().split('VmRSS:')[1].split()[0])
    assert rss < 1_500_000
    app.click('Step >')
    assert app.state()['cursor'] == pytest.approx(0.1)
  finally:
    app.close()


def test_four_cameras_seek(tmp_path):
  app = App(tmp_path, layout='cameras.json')
  try:
    names = ['road camera', 'qroad camera', 'wide_road camera', 'driver camera']
    app.wait(lambda s: all(s.get('plots', {}).get(name, {}).get('frame', -1) == 0 for name in names), timeout=30)
    app.click('Step >')
    app.wait(lambda s: all(s.get('plots', {}).get(name, {}).get('frame', -1) == 2 for name in names))
    app.click('< Step')
    app.wait(lambda s: all(s.get('plots', {}).get(name, {}).get('frame', -1) == 0 for name in names))
  finally:
    app.close()


def test_remote_stream(tmp_path):
  app = App(tmp_path, live=True, remote=True)
  try:
    state = app.wait(lambda s: s.get('cursor', 0) > 5, timeout=20)
    assert state['channels'] > 50
    assert state['data_last'] - state['data_first'] <= 1.001
  finally:
    app.close()


def test_transforms_split_undo_save_and_logs(app):
  app.click('Pane')
  app.click('Curve /carState/vEgo')
  app.click('First derivative')
  app.click('Apply')
  state = app.wait(lambda s: s.get('plots', {}).get('/carState/vEgo', {}).get('count') == 999)
  assert state['plots']['/carState/vEgo']['first'] == pytest.approx(2, abs=1e-5)
  app.click('Pane')
  app.click('Split top / bottom')
  app.wait(lambda s: len(s['layout']['tabs'][0]['root']['children'][0]['children']) == 2)
  app.x('key', '--delay', 80, 'ctrl+z')
  app.wait(lambda s: not s['layout']['tabs'][0]['root']['children'][0]['children'])
  app.x('key', '--delay', 80, 'ctrl+s')
  time.sleep(0.3)
  saved = json.loads((app.directory / 'layout.json').read_text())
  assert saved['tabs'][0]['root']['children'][0]['curves'][0]['derivative']
  app.click('Tab Logs')
  app.text('Search logs', 'fixture sample 100')
  app.click('Log row 0')
  assert app.state()['cursor'] == pytest.approx(1)


@pytest.mark.parametrize('selector', ['q', 'r', 'a'])
def test_local_route_selectors(tmp_path, selector):
  app = App(tmp_path, route=selector)
  try:
    app.wait(lambda s: s.get('plots', {}).get('/carState/vEgo', {}).get('count') == 1000)
    if 'Pause' in app.state()['items']:
      app.click('Pause')
    app.click('Step >')
    app.wait(lambda s: s['cursor'] >= 0.1)
    assert app.state()['logs'] == 100
  finally:
    app.close()


def test_map_seek_zoom_and_follow(app):
  state = app.wait(lambda s: 'GPS canvas' in s['items'])
  x1, y1, x2, y2 = state['items']['GPS canvas'][0]
  app.x('mousemove', int((x1 + x2) / 2), int((y1 + y2) / 2))
  time.sleep(0.1)
  app.x('mousedown', 1)
  time.sleep(0.1)
  app.x('mouseup', 1)
  app.wait(lambda s: 2 < s['cursor'] < 8)
  app.x('click', '--repeat', 5, '--delay', 80, 4)
  app.click('Fit route')
  assert app.process.poll() is None


def test_close_during_load_and_corrupt_input(app):
  damaged = app.directory / 'damaged-log'
  damaged.write_bytes((app.directory / 'rlog').read_bytes()[:12345] + b'\xff' * 8192)
  for index, delay in enumerate([0.05, 0.2, 0.5, 1, 2]):
    env = dict(app.env, XDG_CONFIG_HOME=str(app.directory / f'close-config-{index}'))
    with (app.directory / f'close-{index}.log').open('w') as output:
      process = subprocess.Popen([str(BINARY), str(damaged), '--analysis'], env=env, stdout=output, stderr=subprocess.STDOUT)
      try:
        time.sleep(delay)
        if process.poll() is None:
          process.terminate()
        assert process.wait(timeout=20) in (0, -15)
      finally:
        if process.poll() is None:
          process.kill()
          process.wait()


def test_can_decode_and_multiselect(app):
  app.text('Search signals', '/can/0/FIXTURE/COUNTER')
  app.click('/can/0/FIXTURE/COUNTER', twice=True)
  state = app.wait(lambda s: '/can/0/FIXTURE/COUNTER' in s['plots'])
  assert state['plots']['/can/0/FIXTURE/COUNTER']['last'] == 999
  app.text('Search signals', '/carState/')
  app.click('/carState/aEgo')
  app.x('keydown', 'ctrl')
  app.click('/carState/brakePressed')
  app.x('keyup', 'ctrl')
  app.click('Pane')
  app.click('Add selected signals')
  app.wait(lambda s: '/carState/brakePressed' in s['plots'] and '/carState/aEgo' in s['plots'])


def test_tab_order_persists(app):
  app.click('Tab Logs')
  app.x('click', 3)
  app.click('Move tab left')
  app.wait(lambda s: s['layout']['tabs'][0]['name'] == 'Logs')
  app.x('key', '--delay', 80, 'ctrl+s')
  time.sleep(0.3)
  assert json.loads((app.directory / 'layout.json').read_text())['tabs'][0]['name'] == 'Logs'


def test_timeline_seek_preserves_playback(app):
  def seek(fraction):
    x1, y1, x2, y2 = app.state()['items']['Timeline'][0]
    app.x('mousemove', int(x1 + (x2 - x1) * fraction), int((y1 + y2) / 2), 'mousedown', 1)
    time.sleep(0.08)
    app.x('mouseup', 1)

  seek(0.2)
  app.wait(lambda s: s['cursor'] > 1)
  assert 'Play' in app.state()['items']
  app.click('Play')
  seek(0.6)
  state = app.wait(lambda s: s['cursor'] > 5)
  assert 'Pause' in state['items']
  app.wait(lambda s: s['cursor'] > state['cursor'] + 0.3)
