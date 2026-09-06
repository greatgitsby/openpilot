"""All-service publisher with malformed packets, for isolated live stress tests."""

import time
from openpilot.cereal import messaging

publisher = messaging.PubMaster(['carState', 'longitudinalPlan', 'sendcan'])
time.sleep(1)
for index in range(6000):
  for service in ['carState', 'longitudinalPlan', 'sendcan']:
    message = messaging.new_message(service, 1 if service == 'sendcan' else None)
    message.logMonoTime = 1_000_000_000_000 + index * 10_000_000
    if service == 'carState':
      message.carState.vEgo = index
    elif service == 'longitudinalPlan':
      message.longitudinalPlan.speeds = [index, index + 1]
    else:
      message.sendcan[0].address = 123
      message.sendcan[0].dat = (index % 65536).to_bytes(2, 'little')
    publisher.send(service, message)
  if index % 50 == 0:
    publisher.send('carState', b'\xff' * 8)
  time.sleep(0.001)
