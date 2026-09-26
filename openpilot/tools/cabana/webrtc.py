"""Cabana's Athena/WebRTC client: serves the device's video over VisionIPC and relays CAN and controls.

stdout: packets of !I size + kind + payload, 'C' is a CAN event and 'E' a final error message
stdin: 3 byte commands, 'V' + VisionStreamType to switch cameras or 'J' + gas + steer (int8 percent)
"""
import argparse
import json
import os
import re
import select
import signal
import struct
import sys
import time
import zlib
from urllib.parse import quote

import requests
from libdatachannel import Configuration, Description, H264RtpDepacketizer, IceServer, NalUnit, PeerConnection, RtcpReceivingSession
from msgq.visionipc import VisionIpcServer

from openpilot.cereal.visionipc import VisionStreamType
from openpilot.system.webrtc.webrtcd import CAN_PREFIX
from openpilot.tools.camerastream.ffmpeg_decoder import Decoder, FFmpegError
from openpilot.tools.lib.auth_config import get_token

CAMERAS = {
  VisionStreamType.VISION_STREAM_NARROW_ROAD: "road",
  VisionStreamType.VISION_STREAM_CABIN: "driver",
  VisionStreamType.VISION_STREAM_WIDE_ROAD: "wideRoad",
}
CLOSED = (PeerConnection.State.Disconnected, PeerConnection.State.Failed, PeerConnection.State.Closed)


def ice_servers(session):
  try:
    response = session.get("https://api.comma.ai/v1/me/turn", timeout=10)
    response.raise_for_status()
  except requests.RequestException as e:
    print(f"TURN unavailable, trying a direct connection: {e}", file=sys.stderr)
    return [IceServer("stun:stun.l.google.com:19302")]
  servers = []
  for server in response.json()["iceServers"]:
    credentials = quote(server.get("username", ""), safe="") + ":" + quote(server.get("credential", ""), safe="") + "@"
    for url in [server["urls"]] if isinstance(server["urls"], str) else server["urls"]:
      scheme, address = url.split(":", 1)
      servers.append(IceServer(f"{scheme}:{credentials}{address}" if scheme.startswith("turn") else url))
  return servers


def wait_until(condition, timeout):
  # libdatachannel is polled instead of using callbacks: libdatachannel-py holds the GIL
  # in native calls, so a callback waiting for it can deadlock a concurrent send
  deadline = time.monotonic() + timeout
  while not condition() and time.monotonic() < deadline:
    time.sleep(0.01)


def connect(dongle_id):
  token = get_token()
  if not token:
    raise RuntimeError("Authenticate first: python -m openpilot.tools.lib.auth")
  session = requests.Session()
  session.headers["Authorization"] = "JWT " + token
  config = Configuration()
  config.disable_auto_negotiation = True
  config.force_media_transport = True
  config.ice_servers = ice_servers(session)
  pc = PeerConnection(config)
  channel = pc.create_data_channel("data")
  media = Description.Video("wideRoad", Description.Direction.RecvOnly)
  media.add_h264_codec(96)
  track = pc.add_track(media)
  track.set_media_handler(H264RtpDepacketizer(NalUnit.Separator.StartSequence))
  track.chain_media_handler(RtcpReceivingSession())  # receiver reports drive the device's bitrate control

  # like Connect, offer the first relay candidate rather than waiting for every TURN server
  pc.set_local_description(Description.Type.Offer)
  wait_until(lambda: pc.gathering_state() == PeerConnection.GatheringState.Complete or " typ relay" in str(pc.local_description()), 8)
  response = session.post(f"https://athena.comma.ai/{dongle_id}", timeout=45, json={
    "jsonrpc": "2.0", "id": 1, "method": "startStream",
    "params": {"sdp": str(pc.local_description()), "enabled": True, "can": True},
  })
  response.raise_for_status()
  payload = response.json()
  result = payload.get("result", {})
  if "sdp" not in result:
    raise RuntimeError(str(result.get("message") or payload.get("error") or result))
  pc.set_remote_description(Description(result["sdp"], Description.Type.Answer))
  wait_until(lambda: channel.is_open() or pc.state() in CLOSED, 20)
  if not channel.is_open():
    raise TimeoutError("Timed out connecting to the device. Check device and network connectivity.")
  return pc, channel, track


def stream(pc, channel, track, server_name, emit):
  decoder = Decoder("h264")
  camera = VisionStreamType.VISION_STREAM_WIDE_ROAD
  vipc, size, frame_id, can_bytes, commands = None, None, 0, 0, b""
  while pc.state() not in CLOSED and channel.is_open():
    while (message := channel.receive()) is not None:
      if isinstance(message, bytes) and message.startswith(CAN_PREFIX):
        emit(b"C", zlib.decompress(message[len(CAN_PREFIX):]))
        can_bytes += len(message)
        channel.send(json.dumps({"type": "canAck", "data": {"bytes": can_bytes}}))
      elif (payload := json.loads(message)).get("type") == "disconnect":
        raise RuntimeError(payload["data"])

    while (frame := track.receive()) is not None:
      try:
        image = decoder.decode(frame)
      except FFmpegError:
        continue  # the stream encoder sends a keyframe every 5 frames
      if image is None:
        continue
      if size != (decoder.width, decoder.height):
        size = w, h = decoder.width, decoder.height
        vipc = None  # release the server name before recreating it
        vipc = VisionIpcServer(server_name)
        for stream_type in CAMERAS:
          vipc.create_buffers_with_sizes(stream_type, 4, w, h, w * h * 3 // 2, w, w * h)
        vipc.start_listener()
      now = time.monotonic_ns()
      vipc.send(camera, image, frame_id, now, now)
      frame_id += 1

    if select.select([sys.stdin], [], [], 0.005)[0]:
      data = os.read(sys.stdin.fileno(), 4096)
      if not data:
        return  # Cabana closed the stream
      commands += data
      while len(commands) >= 3:
        kind, a, b = struct.unpack("cbb", commands[:3])
        commands = commands[3:]
        if kind == b"V" and a in CAMERAS and a != camera:
          camera = VisionStreamType(a)
          decoder.reset()  # drops the old camera's frames until the next keyframe
          channel.send(json.dumps({"type": "livestreamCameraSwitch", "data": {"camera": CAMERAS[camera]}}))
        elif kind == b"J":
          channel.send(json.dumps({"type": "testJoystick", "data": {"axes": [a / 100, b / 100], "buttons": [False]}}))
  raise RuntimeError("WebRTC disconnected, reopen the stream to reconnect.")


def main():
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("dongle_id")
  parser.add_argument("--server", required=True, help="VisionIPC server name")
  args = parser.parse_args()

  # keep stdout for packets, native libraries print to it too
  output = os.fdopen(os.dup(sys.stdout.fileno()), "wb")
  os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

  def emit(kind, payload):
    output.write(struct.pack("!I", len(payload) + 1) + kind + payload)
    output.flush()

  signal.signal(signal.SIGTERM, lambda *_: sys.exit())
  pc = None
  status = 0
  try:
    if not re.fullmatch(r"[0-9a-fA-F]{16}", args.dongle_id):
      raise ValueError("Enter the device's 16 character dongle ID.")
    pc, channel, track = connect(args.dongle_id)
    stream(pc, channel, track, args.server, emit)
  except (BrokenPipeError, ConnectionResetError):
    pass  # Cabana exited
  except Exception as e:
    status = 1
    print(e, file=sys.stderr)
    try:
      emit(b"E", (str(e) or type(e).__name__).encode())
    except OSError:
      pass
  finally:
    if pc is not None:
      pc.close()  # tells the device right away
    os._exit(status)  # skip interpreter teardown of the native objects


if __name__ == "__main__":
  main()
