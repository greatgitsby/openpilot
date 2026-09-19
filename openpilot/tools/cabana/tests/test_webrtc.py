import unittest
from unittest.mock import Mock, patch

from opendbc.car.structs import car
from openpilot.common.params import Params, ParamKeyFlag
from openpilot.common.test import OpenpilotTestCase
from openpilot.system.athena import athenad
from openpilot.system.manager.process_config import managed_processes
from openpilot.cereal import messaging
from openpilot.system.webrtc.webrtcd import CerealOutgoingMessageProxy
from openpilot.tools.cabana.webrtc import can_event, ice_servers


class TestWebRTCCan(unittest.TestCase):
  def test_binary_events_are_drained_without_conflation(self):
    events = []
    for i in range(3):
      msg = messaging.new_message("can", 2)
      msg.logMonoTime = 123456789 + i
      for j, frame in enumerate(msg.can):
        frame.address = 0x123 + j
        frame.src = j
        frame.dat = b"\x00\xff\x80\x01"
      events.append(msg.to_bytes())

    sock = Mock()
    sock.receive.side_effect = [*events, None]
    channel = Mock()
    channel.is_open.return_value = True
    channel.buffered_amount.return_value = 0
    with patch.object(messaging, "sub_sock", return_value=sock) as sub_sock, patch.object(messaging, "SubMaster") as submaster:
      submaster.return_value.updated = {}
      proxy = CerealOutgoingMessageProxy(["can", "carState"])
      proxy.add_channel(channel)
      proxy.update()
      sub_sock.assert_called_once_with("can", conflate=False)
      submaster.assert_called_once_with(["carState"])

    received = [can_event(call.args[0]) for call in channel.send.call_args_list]
    self.assertEqual(received, events)

  def test_slow_reader_disconnects_instead_of_unbounded_buffering(self):
    sock = Mock()
    sock.receive.return_value = b"data"
    channel = Mock()
    channel.is_open.return_value = True
    channel.buffered_amount.return_value = 5 * 1024 * 1024
    with patch.object(messaging, "sub_sock", return_value=sock), patch.object(messaging, "SubMaster"):
      proxy = CerealOutgoingMessageProxy(["can"])
      proxy.add_channel(channel)
      proxy.update()
    channel.close.assert_called_once()
    self.assertIn("cannot keep up", channel.send.call_args.args[0])

  def test_reject_invalid_binary_events(self):
    self.assertIsNone(can_event('{"type":"carState"}'))
    self.assertIsNone(can_event(b'{"type":"carState"}'))
    with self.assertRaises(ValueError):
      can_event(b"CAN\0bad")
    msg = messaging.new_message("carState")
    with self.assertRaises(ValueError):
      can_event(b"CAN\0" + msg.to_bytes())

  def test_turn_configuration(self):
    session = Mock()
    session.get.return_value.json.return_value = {"iceServers": [
      {"urls": "stun:stun.example.com:3478"},
      {"urls": ["turn:relay.example.com:3478?transport=udp", "turns:relay.example.com:5349"],
       "username": "user", "credential": "password"},
    ]}
    servers = ice_servers(session)
    self.assertEqual(len(servers), 3)


class TestWebRTCLifecycle(OpenpilotTestCase):
  def test_stream_survives_ignition(self):
    params = Params()
    params.put_bool("IsLiveStreaming", True, block=True)
    params.clear_all(ParamKeyFlag.CLEAR_ON_IGNITION_ON)
    self.assertTrue(params.get_bool("IsLiveStreaming"))
    cp = car.CarParams.new_message()
    for started in (False, True, False):
      for name in ("webrtcd", "stream_encoderd", "camerad"):
        self.assertTrue(managed_processes[name].should_run(started, params, cp), name)
    params.put_bool("IsLiveStreaming", False, block=True)
    self.assertTrue(managed_processes["webrtcd"].should_run(False, params, cp))
    self.assertFalse(managed_processes["stream_encoderd"].should_run(False, params, cp))
    self.assertTrue(managed_processes["stream_encoderd"].should_run(True, params, cp))

  def test_athena_can_is_opt_in(self):
    with patch("openpilot.system.webrtc.helpers.wait_for_webrtcd"), \
         patch("openpilot.system.webrtc.helpers.post_stream_request", return_value={"sdp": "answer"}) as post:
      athenad.startStream("offer", True)
      self.assertEqual(post.call_args.args[0].bridge_services_out, ["carState", "deviceState"])
      athenad.startStream("offer", True, can=True)
      self.assertEqual(post.call_args.args[0].bridge_services_out, ["carState", "deviceState", "can"])
      self.assertTrue(Params().get_bool("IsLiveStreaming"))


if __name__ == "__main__":
  unittest.main()
