import asyncio
import json
import os
import time
import zlib

import capnp
from openpilot.common.test import OpenpilotTestCase
from openpilot.cereal import messaging, log
from teleoprtc.tracks import VIDEO_CLOCK_RATE

from openpilot.system.webrtc.webrtcd import CAN_PREFIX, CAN_WINDOW, CerealOutgoingMessageProxy, CerealIncomingMessageProxy, ServerState, \
                                            StreamSession, handle_get_stream
from openpilot.system.webrtc.device.video import LiveStreamVideoStreamTrack, V4L2_BUF_FLAG_KEYFRAME


class TestStreamSession(OpenpilotTestCase):
  def setup_method(self):
    self.loop = asyncio.new_event_loop()

  def teardown_method(self):
    self.loop.stop()
    self.loop.close()

  def test_outgoing_proxy(self, mocker):
    test_msg = log.Event.new_message()
    test_msg.logMonoTime = 123
    test_msg.valid = True
    test_msg.customReservedRawData0 = b"test"
    expected_dict = {"type": "customReservedRawData0", "logMonoTime": 123, "valid": True, "data": "test"}
    expected_json = json.dumps(expected_dict).encode()

    channel = mocker.Mock()
    channel.is_open.return_value = True
    proxy = CerealOutgoingMessageProxy(["customReservedRawData0"])
    def mocked_update(t):
      proxy.sm.update_msgs(0, [test_msg])

    mocker.patch.object(messaging.SubMaster, "update", side_effect=mocked_update)
    proxy.add_channel(channel)

    proxy.update()

    channel.send.assert_called_once_with(expected_json)

  def test_outgoing_proxy_can(self, mocker):
    events = [os.urandom(4096) for _ in range(100)]
    sock = mocker.Mock()
    sock.receive.side_effect = [*events, None]
    sub_sock = mocker.patch.object(messaging, "sub_sock", return_value=sock)
    channel = mocker.Mock()
    proxy = CerealOutgoingMessageProxy(["can"])
    proxy.add_channel(channel)
    sub_sock.assert_called_once_with("can", conflate=False)

    # unacknowledged bytes are limited to CAN_WINDOW
    proxy.update()
    assert CAN_WINDOW <= proxy.can_sent < CAN_WINDOW + 5000
    session = mocker.Mock(outgoing_bridge=proxy)
    StreamSession.message_handler(session, json.dumps({"type": "canAck", "data": {"bytes": proxy.can_sent}}).encode())
    proxy.update()
    received = [zlib.decompress(call.args[0].removeprefix(CAN_PREFIX)) for call in channel.send.call_args_list]
    assert received == events

  def test_incoming_proxy(self, mocker):
    tested_msgs = [
      {"type": "customReservedRawData0", "data": "test"}, # primitive
      {"type": "can", "data": [{"address": 0, "dat": "", "src": 0}]}, # list
      {"type": "testJoystick", "data": {"axes": [0, 0], "buttons": [False]}}, # dict
    ]

    mocked_pubmaster = mocker.MagicMock(spec=messaging.PubMaster)

    proxy = CerealIncomingMessageProxy(mocked_pubmaster)

    for msg in tested_msgs:
      proxy.send(json.dumps(msg).encode())

      mocked_pubmaster.send.assert_called_once()
      mt, md = mocked_pubmaster.send.call_args.args
      msg_type = msg["type"]
      assert isinstance(msg_type, str)
      assert mt == msg_type
      assert isinstance(md, capnp._DynamicStructBuilder)
      assert hasattr(md, msg_type)

      mocked_pubmaster.reset_mock()

  def test_livestream_track(self, mocker):
    fake_msg = messaging.new_message("livestreamCabinEncodeData")

    config = {"receive.return_value": fake_msg.to_bytes()}
    mocker.patch("msgq.SubSocket", spec=True, **config)
    track = LiveStreamVideoStreamTrack("driver")

    assert track.id.startswith("driver")

    for i in range(5):
      packet = self.loop.run_until_complete(track.recv())
      if i == 0:
        start_ns = time.monotonic_ns()
        start_pts = packet.pts
      assert abs(i + packet.pts - (start_pts + (((time.monotonic_ns() - start_ns) * VIDEO_CLOCK_RATE) // 1_000_000_000))) < 450 #5ms
      assert bytes(packet) == b""

  def test_keyframe_request_clears(self, mocker):
    keyframe = messaging.new_message("livestreamWideRoadEncodeData")
    keyframe.livestreamWideRoadEncodeData.idx.flags = V4L2_BUF_FLAG_KEYFRAME
    mocker.patch("msgq.SubSocket", spec=True, **{"receive.return_value": keyframe.to_bytes()})
    params = mocker.patch("openpilot.system.webrtc.device.video.Params").return_value
    track = LiveStreamVideoStreamTrack("wideRoad")
    self.loop.run_until_complete(track.recv())
    track.request_keyframe()
    self.loop.run_until_complete(track.recv())
    assert [call.args[1] for call in params.put.call_args_list] == [False, True, False]

  def test_stream_rejects_non_json_content_type(self):
    response = self.loop.run_until_complete(handle_get_stream(ServerState(), b"{}", "text/plain"))

    assert response == (415, b'{"error": "unsupported media type"}', "application/json; charset=utf-8")
