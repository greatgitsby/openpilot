"""Native binding regression: a video callback must not deadlock a CAN send."""
import subprocess
import sys
import unittest


class TestNativeWebRTC(unittest.TestCase):
  def test_turn_tcp_is_supported(self):
    # A local TURN listener verifies the installed backend actually attempts TCP.
    # The upstream libjuice build silently ignores this transport.
    result = subprocess.run([sys.executable, "-c", r'''
import os
import socket
from libdatachannel import Configuration, PeerConnection, IceServer

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
listener.settimeout(5)
config = Configuration()
config.ice_servers = [IceServer("127.0.0.1", listener.getsockname()[1], "user", "password", IceServer.RelayType.TurnTcp)]
pc = PeerConnection(config)
channel = pc.create_data_channel("data")
connection, _ = listener.accept()
connection.settimeout(5)
header = b""
while len(header) < 20:
  data = connection.recv(20 - len(header))
  assert data, "TURN connection closed before Allocate request"
  header += data
assert header[:2] == b"\x00\x03", "Expected TURN Allocate request"
assert header[4:8] == b"\x21\x12\xa4\x42", "Expected STUN magic cookie"
os._exit(0)
'''], capture_output=True, text=True, timeout=10)
    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

  def test_send_during_keyframe_callback(self):
    # Isolate native crashes/deadlocks and the binding's interpreter teardown.
    result = subprocess.run([sys.executable, "-c", r'''
import os
import threading
import time
from libdatachannel import Configuration, Description, PeerConnection, PliHandler, RtcpReceivingSession

config = Configuration()
config.disable_auto_negotiation = True
config.force_media_transport = True
viewer, device = PeerConnection(config), PeerConnection(config)
gathered = [threading.Event(), threading.Event()]
for pc, event in zip((viewer, device), gathered):
  pc.on_gathering_state_change(lambda state, event=event: event.set()
                             if state == PeerConnection.GatheringState.Complete else None)
channel = viewer.create_data_channel("data")
received = threading.Event()
channel.on_message(lambda data: received.set() if data == b"CAN\0test" else None)
channels = []
device.on_data_channel(channels.append)
media = Description.Video("wideRoad", Description.Direction.RecvOnly)
media.add_h264_codec(96)
receiver = viewer.add_track(media)
rtcp = RtcpReceivingSession()
receiver.set_media_handler(rtcp)
viewer.set_local_description(Description.Type.Offer)
assert gathered[0].wait(5), "offer gathering timed out"
device.set_remote_description(Description(str(viewer.local_description()), Description.Type.Offer))
media = Description.Video("wideRoad", Description.Direction.SendOnly)
media.add_h264_codec(96)
media.add_ssrc(1234, "test", "test", "wideRoad")
sender = device.add_track(media)
entered = threading.Event()
def keyframe():
  entered.set()
  time.sleep(0.1)  # Model a callback that releases the GIL while holding the transport lock.
pli = PliHandler(keyframe)
sender.set_media_handler(pli)
device.set_local_description(Description.Type.Answer)
assert gathered[1].wait(5), "answer gathering timed out"
viewer.set_remote_description(Description(str(device.local_description()), Description.Type.Answer))
deadline = time.monotonic() + 5
while not channels or not channels[0].is_open():
  assert time.monotonic() < deadline, "data channel did not open"
  time.sleep(0.01)
assert receiver.request_keyframe(), "keyframe request failed"
assert entered.wait(5), "keyframe callback did not run"
print("Sending CAN while the keyframe callback is active", flush=True)
channels[0].send(b"CAN\0test")
assert received.wait(5), "CAN message did not arrive"
viewer.close()
device.close()
os._exit(0)
'''], capture_output=True, text=True, timeout=20)
    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
  unittest.main()
