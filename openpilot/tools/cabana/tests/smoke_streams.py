"""Exercise local msgq and loopback ZMQ cereal reception in the real UI.

Run on an X display after building Cabana and cereal/messaging/bridge.
All local queues and Cabana settings are isolated in temporary directories.
"""
import csv
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

import zmq
from openpilot.cereal import messaging


def run(remote, output):
  prefix = 'cabana-test-' + uuid.uuid4().hex[:12]
  queue = Path('/dev/shm') / ('msgq_' + prefix)
  queue.mkdir()
  previous = os.environ.get('OPENPILOT_PREFIX')
  os.environ['OPENPILOT_PREFIX'] = prefix
  context = zmq.Context()
  publisher = None
  try:
    if remote:
      port_hash = 0xcbf29ce484222325
      for byte in b'carState':
        port_hash = ((port_hash ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
      publisher = context.socket(zmq.PUB)
      publisher.bind(f'tcp://127.0.0.1:{8023 + port_hash % (65535 - 8023)}')
      send = publisher.send
    else:
      publisher = messaging.pub_sock('carState')
      send = publisher.send
    output.mkdir(parents=True)
    env = dict(os.environ, XDG_CONFIG_HOME=str(output), CABANA_PROFILE=str(output / 'frames.csv'))
    env.pop('WAYLAND_DISPLAY', None)
    binary = Path(__file__).resolve().parents[1] / 'cabana'
    with (output / 'app.log').open('w') as log:
      app = subprocess.Popen([str(binary), *(['--zmq', '127.0.0.1'] if remote else ['--msgq'])], env=env, stdout=log, stderr=log)
      try:
        for i in range(300):
          if app.poll() is not None:
            raise RuntimeError((output / 'app.log').read_text())
          message = messaging.new_message('carState')
          message.valid = True
          message.carState.vEgo = float(i)
          send(message.to_bytes())
          time.sleep(.02)
      finally:
        if app.poll() is None:
          app.send_signal(signal.SIGTERM)
        app.wait(timeout=15)
      if app.returncode:
        raise RuntimeError((output / 'app.log').read_text())
    with (output / 'frames.csv').open() as file:
      frames = [list(map(float, row)) for row in csv.reader(file)]
    assert any(fields > 0 for _, _, fields in frames), 'No cereal fields received'
    return {'transport': 'loopback ZMQ bridge' if remote else 'local msgq', 'fields': max(row[2] for row in frames)}
  finally:
    if remote and publisher is not None:
      publisher.close(linger=0)
    publisher = None
    context.term()
    shutil.rmtree(queue)
    if previous is None:
      os.environ.pop('OPENPILOT_PREFIX', None)
    else:
      os.environ['OPENPILOT_PREFIX'] = previous


if __name__ == '__main__':
  with tempfile.TemporaryDirectory(prefix='cabana-streams-') as directory:
    print(json.dumps([run(remote, Path(directory) / str(remote)) for remote in (False, True)], indent=2))
