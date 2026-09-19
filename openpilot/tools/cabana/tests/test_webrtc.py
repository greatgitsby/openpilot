import asyncio
import subprocess
import struct
import os
import zlib
import requests
import time
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

from opendbc.car.structs import car
from openpilot.common.params import Params, ParamKeyFlag
from openpilot.common.test import OpenpilotTestCase
from openpilot.system.athena import athenad
from openpilot.system.manager.process_config import managed_processes
from openpilot.cereal import messaging
from openpilot.system.webrtc.webrtcd import CerealOutgoingMessageProxy, JoystickControl, StreamSession
from openpilot.system.webrtc.can import CAN_WINDOW, MAX_BATCH_SIZE, pack_can_batch, unpack_can_batch
from openpilot.system.webrtc.device.video import LiveStreamVideoStreamTrack
from openpilot.tools.cabana.webrtc import ControlReader, can_event, error_message, ice_servers, wait_for_candidates, wait_for_setup


class TestJoystickControl(unittest.TestCase):
  def test_fragmented_and_combined_commands(self):
    reader = ControlReader()
    self.assertEqual(reader.feed(b'J\x19'), [])
    self.assertEqual(reader.feed(b'\xe7\x00\x01M\x01'), [
      ("testJoystick", {"axes": [0.25, -0.25], "buttons": [False]}),
      ("camera", 1), ("joystickMode", {"enabled": True}),
    ])
    self.assertEqual(reader.feed(b'J\x00\x00\x00'), [
      ("testJoystick", {"axes": [0, 0], "buttons": [False]}),
    ])

  def test_invalid_commands_are_not_forwarded(self):
    reader = ControlReader()
    self.assertEqual(reader.feed(b'M\x05' + b'J' + struct.pack('bbB', 127, 0, 0)), [])
    self.assertEqual(reader.feed(b'\x02'), [("camera", 2)])

  def controller(self, onroad=False, enabled=False, body=False):
    cp = car.CarParams.new_message()
    cp.notCar = body
    params = Mock()
    params.get.return_value = cp.to_bytes()
    values = {"IsOffroad": not onroad, "JoystickDebugMode": enabled}
    params.get_bool.side_effect = lambda key: values[key]
    params.put_bool.side_effect = lambda key, value, **kwargs: values.update({key: value})
    return JoystickControl(params), params

  def test_mode_changes_only_offroad(self):
    control, params = self.controller(onroad=True)
    self.assertIn("Turn the car off", control.mode({"enabled": True})["data"]["error"])
    params.put_bool.assert_not_called()
    self.assertFalse(control.enabled())
    control, params = self.controller()
    self.assertTrue(control.mode({"enabled": True})["data"]["enabled"])
    self.assertFalse(control.mode({"enabled": False})["data"]["enabled"])

  def test_controls_require_mode_and_finite_normalized_axes(self):
    control, _ = self.controller()
    self.assertFalse(control.valid({"axes": [0, 0], "buttons": [False]}))
    control.mode({"enabled": True})
    self.assertTrue(control.valid({"axes": [1, -1], "buttons": [False]}))
    for axes in ([float('nan'), 0], [float('inf'), 0], [1.1, 0], [0], [True, 0]):
      self.assertFalse(control.valid({"axes": axes, "buttons": [False]}))

  def test_body_does_not_change_car_debug_mode(self):
    control, params = self.controller(body=True, onroad=True)
    self.assertTrue(control.mode({})["data"]["enabled"])
    self.assertTrue(control.valid({"axes": [0.25, -0.25], "buttons": [False]}))
    params.put_bool.assert_not_called()


class TestWebRTCExit(unittest.TestCase):
  def run_helper(self, closed, failure):
    script = f'''
import os
import sys
from openpilot.tools.cabana import webrtc
if {closed!r}:
  reader, writer = os.pipe()
  os.close(reader)
  os.dup2(writer, sys.stdout.fileno())
  os.close(writer)
async def run(dongle_id, server, emit, control_fd):
  if {failure!r}:
    raise RuntimeError("connection failed")
  emit(b'C', b'can event')
webrtc.run = run
sys.argv = ['webrtc', '0123456789abcdef', '--server', 'test']
webrtc.main()
'''
    return subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)

  def test_gui_closes_during_can_write(self):
    result = self.run_helper(closed=True, failure=False)
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stderr, b"")

  def test_gui_closes_before_error_report(self):
    result = self.run_helper(closed=True, failure=True)
    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stderr, b"")

  def test_connection_failure_is_still_reported(self):
    result = self.run_helper(closed=False, failure=True)
    self.assertEqual(result.returncode, 1)
    self.assertEqual(result.stdout, b'\x00\x00\x00\x12Econnection failed')
    self.assertEqual(result.stderr, b'connection failed\n')


class TestWebRTCSetup(unittest.IsolatedAsyncioTestCase):
  async def test_gathering_deadline_allows_partial_offer(self):
    done = asyncio.get_running_loop().create_future()
    with patch("openpilot.tools.cabana.webrtc.ICE_GATHER_DEADLINE", 0):
      self.assertTrue(await wait_for_candidates(asyncio.Event(), done))

  async def test_candidate_ready_sends_offer_without_waiting(self):
    ready = asyncio.Event()
    ready.set()
    done = asyncio.get_running_loop().create_future()
    self.assertTrue(await asyncio.wait_for(wait_for_candidates(ready, done), 0.1))

  async def test_gathering_disconnect_does_not_send_offer(self):
    done = asyncio.get_running_loop().create_future()
    done.set_result(None)
    self.assertFalse(await wait_for_candidates(asyncio.Event(), done))

  async def test_keyframe_callback_defers_parameter_write(self):
    msg = messaging.new_message("livestreamWideRoadEncodeData")
    with patch.object(LiveStreamVideoStreamTrack, "_make_sock"), \
         patch("openpilot.system.webrtc.device.video.Params") as params, \
         patch.object(messaging, "recv_one_or_none", return_value=msg):
      track = LiveStreamVideoStreamTrack("wideRoad")
      track._seen_keyframe = True
      track.request_keyframe()
      track.request_keyframe()
      params.return_value.put.assert_not_called()
      await track.recv()
      params.return_value.put.assert_called_once_with("LivestreamRequestKeyframe", True, block=False)
      await track.recv()
      self.assertEqual(params.return_value.put.call_count, 1)
      track.stop()

  async def test_camera_switch_waits_for_new_keyframe(self):
    predicted = messaging.new_message("livestreamCabinEncodeData")
    predicted.livestreamCabinEncodeData.data = b"predicted"
    keyframe = messaging.new_message("livestreamCabinEncodeData")
    keyframe.livestreamCabinEncodeData.idx.flags = 8
    keyframe.livestreamCabinEncodeData.data = b"keyframe"
    with patch.object(LiveStreamVideoStreamTrack, "_make_sock") as make_sock, \
         patch("openpilot.system.webrtc.device.video.Params") as params, \
         patch.object(messaging, "recv_one_or_none", side_effect=[predicted, keyframe]):
      track = LiveStreamVideoStreamTrack("wideRoad")
      track._seen_keyframe = True
      track.switch_camera("driver")
      make_sock.assert_called_with("driver")
      self.assertFalse(track._seen_keyframe)
      self.assertEqual(bytes(await track.recv()), b"keyframe")
      self.assertTrue(track._seen_keyframe)
      self.assertEqual([call.args[1] for call in params.return_value.put.call_args_list], [True, False])
      track.stop()

  async def test_timeout_has_stage_description(self):
    done = asyncio.get_running_loop().create_future()
    with self.assertRaisesRegex(TimeoutError, "gathering candidates"):
      await wait_for_setup(asyncio.Event(), done, 0, "Timed out gathering candidates")

  async def test_disconnect_during_setup_is_reported(self):
    done = asyncio.get_running_loop().create_future()
    done.set_exception(RuntimeError("Data channel closed"))
    with self.assertRaisesRegex(RuntimeError, "Data channel closed"):
      await wait_for_setup(asyncio.Event(), done, 10, "Timed out")

  async def test_setup_ready(self):
    ready = asyncio.Event()
    ready.set()
    done = asyncio.get_running_loop().create_future()
    self.assertTrue(await wait_for_setup(ready, done, 1, "Timed out"))
    self.assertFalse(done.done())

  async def test_shutdown_during_setup(self):
    done = asyncio.get_running_loop().create_future()
    done.set_result(None)
    self.assertFalse(await wait_for_setup(asyncio.Event(), done, 10, "Timed out"))

  async def test_native_close_does_not_block_http_loop(self):
    session = StreamSession.__new__(StreamSession)
    session._cleanup_lock = asyncio.Lock()
    session._cleanup_done = False
    session.joystick_used = False
    session.params = Mock()
    session.bitrate_controller = session.outgoing_bridge = None
    session.video_tracks = []
    session.stream = Mock()
    session.stream.stop = AsyncMock()
    session.stream.peer_connection.close.side_effect = lambda: time.sleep(0.2)
    cleanup = asyncio.create_task(session.post_run_cleanup())
    await asyncio.sleep(0.02)
    self.assertFalse(cleanup.done(), "native close blocked the service event loop")
    await cleanup
    session.stream.stop.assert_awaited_once()

  def test_device_startup_retries_read_timeout(self):
    from openpilot.system.webrtc.helpers import wait_for_webrtcd
    with patch("openpilot.system.webrtc.helpers.requests.get", side_effect=[requests.ReadTimeout(), Mock(ok=True)]) as get, \
         patch("openpilot.system.webrtc.helpers.time.sleep"):
      wait_for_webrtcd()
      self.assertEqual(get.call_count, 2)

  def test_empty_exception_has_fallback(self):
    self.assertEqual(error_message(TimeoutError()), "TimeoutError")
    self.assertEqual(error_message(RuntimeError("connection failed")), "connection failed")


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

    received = [event for call in channel.send.call_args_list for event in unpack_can_batch(call.args[0])]
    self.assertEqual(received, events)

  def test_slow_reader_applies_backpressure_then_resumes(self):
    sock = Mock()
    sock.receive.return_value = os.urandom(1024)
    channel = Mock()
    channel.is_open.return_value = True
    channel.send.return_value = False
    with patch.object(messaging, "sub_sock", return_value=sock), patch.object(messaging, "SubMaster"):
      proxy = CerealOutgoingMessageProxy(["can"])
      proxy.add_channel(channel)
      while proxy.sent_bytes[channel] < CAN_WINDOW:
        proxy.update()
      count = sock.receive.call_count
      sent = channel.send.call_count
      proxy.update()
      self.assertEqual(sock.receive.call_count, count)
      self.assertEqual(channel.send.call_count, sent)
      proxy.acknowledge(channel, proxy.sent_bytes[channel])
      proxy.update()
      self.assertGreater(channel.send.call_count, sent)
    channel.close.assert_not_called()
    channel.buffered_amount.assert_not_called()

  def test_buffered_sends_can_drain_without_ever_returning_true(self):
    channel = Mock()
    channel.is_open.return_value = True
    channel.send.return_value = False
    sock = Mock()
    with patch.object(messaging, "sub_sock", return_value=sock), patch.object(messaging, "SubMaster"):
      proxy = CerealOutgoingMessageProxy(["can"])
      proxy.add_channel(channel)
      for _ in range(100):
        sock.receive.side_effect = [os.urandom(60000), None]
        proxy.update()
        proxy.acknowledge(channel, proxy.sent_bytes[channel])
      self.assertGreater(proxy.sent_bytes[channel], 4 * 1024 * 1024)
      self.assertEqual(channel.send.call_count, 100)
      proxy.acknowledge(channel, proxy.sent_bytes[channel] + 1)
      proxy.acknowledge(channel, -1)
      self.assertEqual(proxy.acked_bytes[channel], proxy.sent_bytes[channel])
    channel.close.assert_not_called()

  def test_batch_boundaries_preserve_events(self):
    events = [os.urandom(32000) for _ in range(3)]
    sock, channel = Mock(), Mock()
    channel.is_open.return_value = True
    sock.receive.side_effect = [*events, None]
    with patch.object(messaging, "sub_sock", return_value=sock), patch.object(messaging, "SubMaster"):
      proxy = CerealOutgoingMessageProxy(["can"])
      proxy.add_channel(channel)
      proxy.update()
      proxy.update()
      proxy.update()
    self.assertEqual([e for call in channel.send.call_args_list for e in unpack_can_batch(call.args[0])], events)

  def test_reject_invalid_compressed_batches(self):
    for message in (b'CANZbad', b'CANZ'+zlib.compress(b'x'*(MAX_BATCH_SIZE+1)),
                    b'CANZ'+zlib.compress(b'\x00'), b'CANZ'+zlib.compress(struct.pack('!I', 8)),
                    pack_can_batch([b'x'*8])[:-1]):
      with self.assertRaises((ValueError, zlib.error)):
        unpack_can_batch(message)

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
      cp = car.CarParams.new_message()
      cp.notCar = False
      Params().put("CarParamsPersistent", cp.to_bytes())
      athenad.startStream("offer", True, joystick=True)
      self.assertEqual(post.call_args.args[0].bridge_services_in, ["testJoystick"])
      athenad.startStream("offer", True)
      self.assertEqual(post.call_args.args[0].bridge_services_in, [])


if __name__ == "__main__":
  unittest.main()
