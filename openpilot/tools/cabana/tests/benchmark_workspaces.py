"""Measure a local route with repeated, independently docked panes.

Run under an X display (e.g. xvfb-run) after building Cabana. Results contain
index publication time, peak RSS, and frame times excluding intentional pacing.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import time


def layout(count):
  panes = [{'id': f'benchmark-{i}', 'title': f'Speed {i+1}', 'curves': [
    {'source': {'kind': 'series', 'path': '/carState/vEgo'}, 'visible': True, 'color': [0, 114, 178, 255]}
  ]} for i in range(count)]
  leaves = [{'panes': ['###Chart/' + p['id']]} for p in panes]
  def split(nodes, axis):
    tree = nodes[-1]
    for i in range(len(nodes)-2, -1, -1):
      tree = {'axis': axis, 'ratio': 1 / (len(nodes)-i), 'children': [nodes[i], tree]}
    return tree
  columns = min(4, count)
  rows = [split(leaves[i:i+columns], 'x') for i in range(0, count, columns)]
  return {'cabana_workspace': 1, 'active_page': 0, 'pages': [{'id': 'benchmark', 'name': 'Benchmark', 'panes': panes,
    'dock': {'axis': 'x', 'ratio': .15, 'children': [
      {'panes': ['###ChartsWindow', '###VideoPanel', '###MessagesPanel', '###CenterWidget']}, split(rows, 'y')]}}],
    'equations': [], 'view_range': [0, 60]}


def run(args, count):
  root = args.output / str(count)
  root.mkdir(parents=True, exist_ok=True)
  workspace = root / 'workspace.json'
  workspace.write_text(json.dumps(layout(count)))
  env = dict(os.environ, XDG_CONFIG_HOME=str(root), CABANA_PROFILE=str(root / 'frames.csv'))
  env.pop('WAYLAND_DISPLAY', None)
  with (root / 'app.log').open('w') as log:
    process = subprocess.Popen([str(args.binary), args.route, '--data_dir', str(args.data_dir), '--no-vipc', '--layout', str(workspace)],
                               stdout=log, stderr=log, env=env)
    peak_kib = 0
    try:
      end = time.monotonic() + args.seconds
      while time.monotonic() < end and process.poll() is None:
        for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
          if line.startswith('VmHWM:'):
            peak_kib = max(peak_kib, int(line.split()[1]))
        time.sleep(.2)
    finally:
      if process.poll() is None:
        process.send_signal(signal.SIGTERM)
      process.wait(timeout=30)
    if process.returncode:
      raise RuntimeError((root / 'app.log').read_text())
  with (root / 'frames.csv').open() as file:
    frames = [tuple(map(float, row)) for row in csv.reader(file)]
  indexed = next((t for t, _, fields in frames if fields > 0), None)
  if indexed is None:
    raise RuntimeError('No cereal data was published')
  rendered = sorted(ms for t, ms, _ in frames if t >= indexed + 2)
  return {'panes': count, 'index_publication_seconds': indexed, 'peak_rss_mib': peak_kib / 1024,
          'median_frame_ms': statistics.median(rendered), 'p95_frame_ms': rendered[int((len(rendered)-1)*.95)],
          'measured_frames': len(rendered)}


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('route')
  parser.add_argument('data_dir', type=Path)
  parser.add_argument('output', type=Path)
  parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'cabana')
  parser.add_argument('--panes', type=int, nargs='+', default=[1, 8, 24])
  parser.add_argument('--seconds', type=float, default=15)
  args = parser.parse_args()
  args.data_dir, args.output, args.binary = args.data_dir.resolve(), args.output.resolve(), args.binary.resolve()
  results = []
  for count in args.panes:
    results.append(run(args, count))
    print(json.dumps(results[-1]), flush=True)
    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
