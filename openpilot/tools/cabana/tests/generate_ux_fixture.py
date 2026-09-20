#!/usr/bin/env python3
"""Generate deterministic local routes and a workspace for manual Cabana UX checks."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess

from openpilot.cereal import log


def generate(root: Path, route_count: int = 2) -> None:
  root = root.expanduser().resolve()
  root.mkdir(parents=True, exist_ok=True)
  dbc = root / 'fixture.dbc'
  dbc.write_text('VERSION ""\nNS_ :\nBS_:\nBU_: TEST\n'
                 'BO_ 123 FIXTURE: 2 TEST\n SG_ COUNTER : 0|16@1+ (1,0) [0|65535] "" TEST\n'
                 'BO_ 456 SECONDARY: 2 TEST\n SG_ COUNTER : 0|16@1+ (1,0) [0|65535] "" TEST\n')
  sources = []
  for route_index, (route, label, base, color) in enumerate([
    ('2026-09-20--10-00-00', 'Route A', 10, 'blue'),
    ('2026-09-20--11-00-00', 'Route B', 40, 'red'),
    ('2026-09-20--12-00-00', 'Route C', 70, 'teal'),
  ][:route_count]):
    folder = root / (route + '--0')
    folder.mkdir(exist_ok=True)
    start = (route_index + 1) * 1_000_000_000_000
    with (folder / 'rlog').open('wb') as output:
      for i in range(1501):
        ns = start + i * 10_000_000
        event = log.Event.new_message(logMonoTime=ns, valid=True)
        state = event.init('carState')
        state.vEgo = base + i / 100
        state.aEgo = 1
        state.vEgoRaw = state.vEgo
        state.canValid = True
        state.gearShifter = 'drive'
        output.write(event.to_bytes())
        event = log.Event.new_message(logMonoTime=ns, valid=True)
        messages = event.init('can', 2)
        for message, address, value in zip(messages, [123, 456], [base * 100 + i, base * 100 + 1500 - i], strict=True):
          message.address, message.src = address, 0
          message.dat = value.to_bytes(2, 'little')
        output.write(event.to_bytes())
        if i % 10 == 0:
          event = log.Event.new_message(logMonoTime=ns, valid=True)
          state = event.init('selfdriveState')
          state.enabled = 200 <= i < 1300
          state.active = state.enabled
          for first, last, status, title in [
            (400, 500, 'normal', 'Fixture information'),
            (700, 800, 'userPrompt', 'Fixture warning'),
            (1000, 1100, 'critical', 'Fixture critical alert'),
          ]:
            if first <= i < last:
              state.alertSize = 'mid'
              state.alertStatus = status
              state.alertText1 = title
              state.alertText2 = label
          output.write(event.to_bytes())
        if i % 5 == 0 and i < 1500:
          for name in ['narrowRoadEncodeIdx', 'cabinEncodeIdx']:
            event = log.Event.new_message(logMonoTime=ns, valid=True)
            index = event.init(name)
            index.frameId = index.encodeId = index.segmentId = index.segmentIdEncode = i // 5
            index.type = 'fullHEVC'
            index.segmentNum = 0
            index.timestampSof, index.timestampEof = ns, ns + 1_000_000
            output.write(event.to_bytes())
    shutil.copyfile(folder / 'rlog', folder / 'qlog')
    for camera, background in [('fcamera', color), ('dcamera', ['green', 'purple', 'orange'][route_index])]:
      title = f'{label} {"ROAD" if camera == "fcamera" else "DRIVER"}'
      subprocess.run([
        'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-f', 'lavfi', '-i',
        f'color=c={background}:size=320x180:rate=20:duration=15', '-vf',
        f"drawtext=text='{title}':fontcolor=white:fontsize=20:x=30:y=70,"
        "drawtext=text='%{n}':fontcolor=white:fontsize=20:x=30:y=110",
        '-c:v', 'libx265', '-crf', '40', '-preset', 'ultrafast', '-x265-params',
        'log-level=error:pools=1:frame-threads=1:keyint=20:bframes=0',
        '-pix_fmt', 'yuv420p', '-f', 'hevc', str(folder / (camera + '.hevc')),
      ], check=True)
    sources.append({
      'id': f'route-{chr(ord("a") + route_index)}', 'label': label,
      'route': '0000000000000000|' + route, 'data_dir': str(root),
      'dbcs': [{'file': str(dbc), 'buses': [0]}],
    })
  charts = {
    'cabana_layout': 4, 'range': 15,
    'charts': [{'id': '1', 'title': 'Speed comparison (m/s)', 'type': 0, 'signals': [
      {'source': source['id'], 'path': '/carState/vEgo', 'color': color}
      for source, color in zip(sources, ['#36a9e1', '#ee7744', '#30b090'][:route_count], strict=True)
    ]}], 'equations': [],
  }
  widgets = [{'kind': kind, 'source': source['id']} for source in sources for kind in ['can', 'logs']]
  widgets.extend(
    {'kind': 'camera', 'id': f"{source['id']}-{camera}", 'source': source['id'], 'camera': camera, 'crop': False}
    for source in sources for camera in [0, 1]
  )
  workspace = {
    'cabana_workspace': 2, 'name': f'{route_count} local routes', 'default': False, 'include_routes': True,
    'charts': charts, 'ui': '', 'timeline_visible': True, 'sources': sources, 'widgets': widgets,
    'timeline': {'selected': 'route-a', 'camera': 0, 'linked': [],
                 'offsets': {source['id']: 0 for source in sources}, 'loop': False, 'loop_start': 2, 'loop_end': 12},
  }
  for filename, document in [('workspace.json', workspace), ('layout.json', charts)]:
    (root / filename).write_text(json.dumps(document, indent=2) + '\n')
  print(f'Generated {route_count} 15-second routes, {route_count * 2} camera videos, and {root / "workspace.json"}')


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('output_dir', type=Path, help='Directory for generated files (existing fixture files are replaced)')
  parser.add_argument('--routes', type=int, choices=[2, 3], default=2, help='Include a third route for independent/group playback checks')
  args = parser.parse_args()
  generate(args.output_dir, args.routes)
