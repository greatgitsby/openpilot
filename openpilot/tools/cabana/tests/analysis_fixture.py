"""Deterministic local route for UI, replay, and high-volume analysis tests."""

import argparse
import io
import json
from pathlib import Path

from PIL import Image
from openpilot.cereal import log


def generate(directory: Path, count=1000):
  directory.mkdir(parents=True, exist_ok=True)
  thumb = io.BytesIO()
  Image.new('RGB', (320, 180), (25, 125, 180)).save(thumb, format='JPEG')
  with (directory / 'rlog').open('wb') as output:
    for i in range(count):
      timestamp = 1_000_000_000_000 + i * 10_000_000

      def event(service, timestamp=timestamp):
        message = log.Event.new_message(logMonoTime=timestamp, valid=True)
        message.init(service)
        return message

      message = event('carState')
      message.carState.vEgo = i * 0.02
      message.carState.aEgo = 2
      message.carState.steeringAngleDeg = (i % 100) - 50
      message.carState.gearShifter = 'drive'
      output.write(message.to_bytes())
      message = event('longitudinalPlan')
      message.longitudinalPlan.speeds = [i * 0.02 + j for j in range(16)]
      output.write(message.to_bytes())
      message = log.Event.new_message(logMonoTime=timestamp, valid=True)
      frames = message.init('can', 1)
      frames[0].address = 123
      frames[0].src = 0
      frames[0].dat = (i % 65536).to_bytes(2, 'little')
      output.write(message.to_bytes())
      if i % 10 == 0:
        message = event('gpsLocationExternal')
        message.gpsLocationExternal.latitude = 33.45 + i * 0.000001
        message.gpsLocationExternal.longitude = -112.07 + i * 0.000001
        output.write(message.to_bytes())
        message = log.Event.new_message(logMonoTime=timestamp, valid=True)
        message.logMessage = json.dumps(
          {'msg': f'fixture sample {i}', 'levelnum': 20 if i % 20 else 40, 'filename': 'fixture.py', 'created': 1_780_000_000 + i * 0.01, 'ctx': {'sample': i}}
        )
        output.write(message.to_bytes())
      if i % 100 == 0:
        message = event('thumbnail')
        message.thumbnail.thumbnail = thumb.getvalue()
        output.write(message.to_bytes())
  (directory / 'fixture.dbc').write_text('''VERSION ""
NS_ :
BS_:
BU_: TEST
BO_ 123 FIXTURE: 2 TEST
 SG_ COUNTER : 0|16@1+ (1,0) [0|65535] "" TEST
''')
  plot = {'title': 'Speed and acceleration', 'curves': [{'name': '/carState/vEgo', 'color': '#36a9e1'}, {'name': '/carState/aEgo', 'color': '#ee7744'}]}
  layout = {
    'tabs': [
      {
        'name': 'Overview',
        'root': {
          'split': 'horizontal',
          'children': [plot, {'split': 'vertical', 'children': [{'title': 'GPS', 'kind': 'map'}, {'title': 'Thumbnail', 'kind': 'thumbnail'}]}],
        },
      },
      {'name': 'Logs', 'root': {'title': 'Logs', 'kind': 'logs'}},
    ]
  }
  (directory / 'layout.json').write_text(json.dumps(layout))
  (directory / 'malformed.json').write_text('{ definitely not JSON')
  (directory / 'truncated.rlog').write_bytes((directory / 'rlog').read_bytes()[:13])


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('directory', type=Path)
  parser.add_argument('--count', type=int, default=1000)
  args = parser.parse_args()
  generate(args.directory, args.count)


def add_cameras(directory: Path, count=1000, resolution="320x180", b_frames=True):
  import subprocess

  duration = count / 100
  with (directory / 'rlog').open('ab') as output:
    for i in range(0, count, 5):
      for service in ['narrowRoadEncodeIdx', 'wideRoadEncodeIdx', 'cabinEncodeIdx', 'qNarrowRoadEncodeIdx']:
        message = log.Event.new_message(logMonoTime=1_000_000_000_000 + i * 10_000_000, valid=True)
        index = message.init(service)
        index.frameId = index.encodeId = index.segmentId = index.segmentIdEncode = i // 5
        index.timestampSof = message.logMonoTime
        index.timestampEof = message.logMonoTime + 1_000_000
        index.type = 'qcameraH264' if service == 'qNarrowRoadEncodeIdx' else 'fullHEVC'
        output.write(message.to_bytes())
  for name, color in [('fcamera.hevc', 'red'), ('ecamera.hevc', 'green'), ('dcamera.hevc', 'blue'), ('qcamera.ts', 'yellow')]:
    codec = 'libx264' if name.endswith('.ts') else 'libx265'
    command = [
      '/usr/bin/ffmpeg' if Path('/usr/bin/ffmpeg').exists() else 'ffmpeg',
      '-y',
      '-v',
      'error',
      '-f',
      'lavfi',
      '-i',
      f'color=c={color}:s={resolution}:r=20:d={duration}',
      '-c:v',
      codec,
      '-preset',
      'ultrafast',
      '-threads',
      '1',
      '-pix_fmt',
      'yuv420p',
    ]
    if codec == 'libx265':
      command += ['-x265-params', 'pools=1:frame-threads=1:log-level=error' + ('' if b_frames else ':bframes=0:keyint=20:min-keyint=20:scenecut=0')]
    if not b_frames:
      command += ['-bf', '0', '-g', '20']
    subprocess.run([*command, str(directory / name)], check=True, capture_output=True)
  layout = {
    'tabs': [
      {
        'name': 'Cameras',
        'root': {
          'split': 'horizontal',
          'children': [
            {'split': 'vertical', 'children': [{'kind': 'camera', 'camera_view': view, 'title': view} for view in ['road', 'qroad']]},
            {'split': 'vertical', 'children': [{'kind': 'camera', 'camera_view': view, 'title': view} for view in ['wide_road', 'driver']]},
          ],
        },
      }
    ]
  }
  (directory / 'cameras.json').write_text(json.dumps(layout))
