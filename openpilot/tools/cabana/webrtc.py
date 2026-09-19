#!/usr/bin/env python3
"""Single-viewer Athena CAN/video receiver. stdout is a framed pipe to Cabana."""
import argparse
import asyncio
import json
import os
import re
import signal
import struct
import sys
import time
from urllib.parse import urlsplit

import requests
from libdatachannel import Configuration, Description, H264RtpDepacketizer, IceServer, NalUnit, PeerConnection, RtcpReceivingSession

from openpilot.cereal import log
from openpilot.cereal.visionipc import VisionStreamType
from msgq.visionipc import VisionIpcServer
from openpilot.tools.camerastream.ffmpeg_decoder import Decoder, FFmpegError
from openpilot.tools.lib.auth_config import get_token


CAN_PREFIX = b"CAN\0"
MAX_EVENT_SIZE = 1024 * 1024


def can_event(message):
  if not isinstance(message, bytes) or not message.startswith(CAN_PREFIX):
    return None
  data = message[len(CAN_PREFIX):]
  if not data or len(data) > MAX_EVENT_SIZE or len(data) % 8:
    raise ValueError("Invalid CAN event size")
  with log.Event.from_bytes(data) as event:
    if event.which() != "can":
      raise ValueError("Expected a CAN event")
  return data


def ice_servers(session):
  response = session.get("https://api.comma.ai/v1/me/turn", timeout=10)
  response.raise_for_status()
  servers = []
  for entry in response.json()["iceServers"]:
    urls = entry["urls"]
    for url in [urls] if isinstance(urls, str) else urls:
      if url.startswith(("turn:", "turns:")):
        parsed = urlsplit(url.replace(":", "://", 1))
        relay = IceServer.RelayType.TurnTls if parsed.scheme == "turns" else (
          IceServer.RelayType.TurnTcp if "transport=tcp" in parsed.query else IceServer.RelayType.TurnUdp)
        servers.append(IceServer(parsed.hostname, parsed.port or (5349 if parsed.scheme == "turns" else 3478),
                                 entry["username"], entry["credential"], relay))
      else:
        servers.append(IceServer(url))
  return servers


async def run(dongle_id, server_name, emit):
  token = get_token()
  if not token:
    raise RuntimeError("Authenticate first: python -m openpilot.tools.lib.auth")
  session = requests.Session()
  session.headers["Authorization"] = "JWT " + token
  config = Configuration()
  config.disable_auto_negotiation = True
  config.force_media_transport = True
  try:
    config.ice_servers = await asyncio.to_thread(ice_servers, session)
  except Exception as e:
    print(f"TURN unavailable, trying direct connection: {e}", file=sys.stderr)
    config.ice_servers = [IceServer("stun:stun.l.google.com:19302")]

  loop = asyncio.get_running_loop()
  done = loop.create_future()
  gathered = asyncio.Event()
  opened = asyncio.Event()
  frames = asyncio.Queue(maxsize=30)
  pc = PeerConnection(config)
  channel = pc.create_data_channel("data")
  media = Description.Video("wideRoad", Description.Direction.RecvOnly)
  media.add_h264_codec(96)
  track = pc.add_track(media)
  depacketizer = H264RtpDepacketizer(NalUnit.Separator.StartSequence)
  rtcp = RtcpReceivingSession()
  track.set_media_handler(depacketizer)
  track.chain_media_handler(rtcp)

  def finish(error=None):
    if not done.done():
      if error:
        done.set_exception(RuntimeError(error))
      else:
        done.set_result(None)

  def on_message(message):
    try:
      data = can_event(message)
      if data is not None:
        emit(b'C', data)
      else:
        payload = json.loads(message)
        if payload.get("type") == "disconnect":
          finish(payload.get("data", "Disconnected"))
    except Exception as e:
      finish(str(e))

  def on_frame(data):
    if frames.full():
      # Dropping encoded frames breaks prediction. Flush and request a keyframe.
      while not frames.empty():
        frames.get_nowait()
      decoder.reset()
      track.request_keyframe()
    frames.put_nowait(data)

  def on_state(state):
    if state in (PeerConnection.State.Failed, PeerConnection.State.Disconnected, PeerConnection.State.Closed):
      loop.call_soon_threadsafe(finish, "WebRTC disconnected; reopen the stream to reconnect.")

  pc.on_state_change(on_state)
  pc.on_gathering_state_change(lambda state: loop.call_soon_threadsafe(gathered.set)
                              if state == PeerConnection.GatheringState.Complete else None)
  channel.on_open(lambda: loop.call_soon_threadsafe(opened.set))
  channel.on_message(lambda message: loop.call_soon_threadsafe(on_message, message))
  channel.on_closed(lambda: loop.call_soon_threadsafe(finish, "WebRTC data channel closed."))
  track.on_frame(lambda data, info: loop.call_soon_threadsafe(on_frame, bytes(data)))
  for sig in (signal.SIGTERM, signal.SIGINT):
    loop.add_signal_handler(sig, finish)

  decoder = Decoder("h264")
  vipc = None
  dimensions = None
  frame_id = 0

  def negotiate():
    response = session.post("https://athena.comma.ai/" + dongle_id, json={
      "jsonrpc": "2.0", "id": 1, "method": "startStream",
      "params": {"sdp": str(pc.local_description()), "enabled": True, "can": True},
    }, timeout=45)
    response.raise_for_status()
    payload = response.json()
    if payload.get("error"):
      raise RuntimeError(str(payload["error"]))
    result = payload["result"]
    if result.get("error"):
      raise RuntimeError(result.get("message", result["error"]))
    return result["sdp"]

  async def receive_video():
    nonlocal vipc, dimensions, frame_id
    while True:
      try:
        data = await asyncio.wait_for(frames.get(), 2)
        image = decoder.decode(data)
      except (TimeoutError, FFmpegError):
        track.request_keyframe()
        continue
      if image is None:
        continue
      size = decoder.width, decoder.height
      if dimensions != size:
        vipc = None
        vipc = VisionIpcServer(server_name)
        width, height = size
        vipc.create_buffers_with_sizes(VisionStreamType.VISION_STREAM_WIDE_ROAD, 4,
                                       width, height, width * height * 3 // 2, width, width * height)
        vipc.start_listener()
        dimensions = size
      now = time.monotonic_ns()
      vipc.send(VisionStreamType.VISION_STREAM_WIDE_ROAD, image, frame_id, now, now)
      frame_id += 1

  video_task = None
  try:
    pc.set_local_description(Description.Type.Offer)
    await asyncio.wait_for(gathered.wait(), 15)
    answer = await asyncio.to_thread(negotiate)
    pc.set_remote_description(Description(answer, Description.Type.Answer))
    await asyncio.wait_for(opened.wait(), 20)
    track.request_keyframe()
    video_task = asyncio.create_task(receive_video())
    completed, _ = await asyncio.wait([done, video_task], return_when=asyncio.FIRST_COMPLETED)
    for task in completed:
      task.result()
  finally:
    if not done.done():
      done.cancel()
    elif not done.cancelled():
      done.exception()  # consume a disconnect that raced with setup/cancellation
    if video_task:
      video_task.cancel()
      await asyncio.gather(video_task, return_exceptions=True)
    pc.close()
    decoder.close()
    session.close()
    # Retain native callback owners until process exit (binding teardown can deadlock).
    _native_owners.extend([pc, channel, track, depacketizer, rtcp])


_native_owners = []


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("dongle_id")
  parser.add_argument("--server", required=True)
  args = parser.parse_args()
  # Native libraries may print to stdout too. Reserve a duplicate for the protocol.
  output = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
  os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

  def emit(kind, payload):
    packet = memoryview(struct.pack("!I", len(payload) + 1) + kind + payload)
    while packet:
      packet = packet[output.write(packet):]

  status = 0
  try:
    if not re.fullmatch(r"[0-9a-fA-F]{16}", args.dongle_id):
      raise ValueError("Enter a 16-character device dongle ID, not an IP address.")
    asyncio.run(run(args.dongle_id, args.server, emit))
  except Exception as e:
    emit(b'E', str(e).encode())
    status = 1
  output.close()
  # Avoid libdatachannel Python callback destruction races during interpreter shutdown.
  os._exit(status)


if __name__ == "__main__":
  main()
