import json
import os
import subprocess
import sys
import unittest
import zlib
from unittest.mock import Mock, patch

import requests
from libdatachannel import IceServer, PeerConnection

from openpilot.cereal import messaging
from openpilot.common.params import Params
from openpilot.common.test import OpenpilotTestCase
from openpilot.system.athena import athenad
from openpilot.system.webrtc.webrtcd import CAN_PREFIX
from openpilot.tools.cabana.webrtc import ice_servers, stream


class TestWebRTC(OpenpilotTestCase):
  def test_start_stream(self):
    params = Params()
    params.put_bool("IsOffroad", False)
    with patch("openpilot.system.webrtc.helpers.wait_for_webrtcd"), \
         patch("openpilot.system.webrtc.helpers.post_stream_request", return_value={"sdp": "answer"}) as post:
      athenad.startStream("offer", True)
      self.assertEqual(post.call_args.args[0].bridge_services_out, ["carState", "deviceState"])
      self.assertFalse(params.get_bool("IsLiveStreaming"))  # Connect only starts streams offroad
      athenad.startStream("offer", True, can=True)
      self.assertEqual(post.call_args.args[0].bridge_services_out, ["can"])
      self.assertTrue(params.get_bool("IsLiveStreaming"))

  def test_ice_servers(self):
    session = Mock()
    session.get.return_value.json.return_value = {"iceServers": [
      {"urls": "stun:stun.example.com:3478"},
      {"urls": ["turn:relay.example.com:3478?transport=udp", "turns:relay.example.com:5349"], "username": "1:user", "credential": "p/w+="},
    ]}
    servers = ice_servers(session)
    self.assertEqual([(s.hostname, s.port, s.username, s.password) for s in servers], [
      ("stun.example.com", 3478, "", ""), ("relay.example.com", 3478, "1:user", "p/w+="), ("relay.example.com", 5349, "1:user", "p/w+=")])
    self.assertEqual(servers[2].relay_type, IceServer.RelayType.TurnTls)
    session.get.side_effect = requests.ConnectionError
    self.assertEqual([s.hostname for s in ice_servers(session)], ["stun.l.google.com"])

  def test_stream(self):
    event = messaging.new_message("can", 1).to_bytes()
    packets = [CAN_PREFIX + zlib.compress(event)]
    pc, channel, track, emit = Mock(), Mock(), Mock(), Mock()
    pc.state.return_value = PeerConnection.State.Connected
    channel.receive.side_effect = lambda: packets.pop() if packets else None
    track.receive.return_value = None
    read, write = os.pipe()
    os.write(write, b"V\x00\x00J\x32\xe7")
    os.close(write)
    with os.fdopen(read, "rb") as stdin, patch.object(sys, "stdin", stdin):
      stream(pc, channel, track, "test", emit)  # returns at EOF, when Cabana closes the stream
    emit.assert_called_once_with(b"C", event)
    self.assertEqual([json.loads(call.args[0]) for call in channel.send.call_args_list], [
      {"type": "canAck", "data": {"bytes": len(CAN_PREFIX + zlib.compress(event))}},
      {"type": "livestreamCameraSwitch", "data": {"camera": "road"}},
      {"type": "testJoystick", "data": {"axes": [0.5, -0.25], "buttons": [False]}},
    ])

  def test_errors_are_reported_to_cabana(self):
    script = "import sys\nfrom openpilot.tools.cabana import webrtc\nwebrtc.connect = lambda dongle_id: 1 / 0\n" + \
             "sys.argv = ['webrtc', '0123456789abcdef', '--server', 'test']\nwebrtc.main()"
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)
    self.assertEqual((result.returncode, result.stdout), (1, b"\x00\x00\x00\x11Edivision by zero"))


if __name__ == "__main__":
  unittest.main()
