# Cabana WebRTC hackathon

## Working scope

- Replace remote ZMQ with `cabana --webrtc <dongle-id>` / Device > Athena / WebRTC.
- One viewer only. Starting an enabled session replaces the previous viewer,
  including comma Connect. Concurrent viewers are intentionally out of scope.
- Athena negotiates the peer connection. H.264 wide-road video and binary CAN
  events travel over WebRTC; TURN credentials come from the authenticated API.
- The daemon is always available. The streaming encoder runs onroad; an active
  session starts/keeps cameras and encoder running offroad. Sessions survive
  ignition transitions and no longer expire after five minutes.
- Raw CAN events retain their device timestamps and bytes. A dedicated,
  non-conflating subscription drains CAN, separate from JSON state telemetry.
- The helper publishes decoded NV12 into a private VisionIPC server and sends
  length-prefixed CAN events to Cabana over a local pipe.

## Caveats for the demo

- Both the device and computer need this branch. Restart openpilot after deployment.
  Old devices reject the new `startStream(..., can=True)` argument. Run Cabana
  from an activated openpilot environment; its helper launches `python3` from PATH.
- Authenticate on the computer using `python -m openpilot.tools.lib.auth`.
  Device/account authorization and TURN availability have not been verified
  against a real comma account/device in this workspace.
- Wide-road camera only. Camera video is always live, independent of CAN pause,
  rewind, and speed. Video is not recorded or synchronized with CAN playback.
- Closing the stream stops the helper. Disconnections require reopening the stream;
  the last camera image may remain visible after an error. There is no reconnect UI.
- Reliable ordered CAN shares the control data channel. Sustained congestion can
  delay controls and telemetry; the device closes the channel above 4 MiB queued.
  This is not a guarantee of lossless capture: the CAN subscription ring can still
  overrun, and no sequence/gap counters are implemented. Prefer device logs for
  authoritative recordings.
- Existing JSON telemetry stays compatible with Connect, which does not opt into
  binary CAN. The binary prefix `CAN\0` is hackathon protocol, not version-negotiated.
- Onroad encoding and unlimited offroad sessions increase resource/power usage.
  Device CPU, encoder capacity, thermals, battery draw, and driving-process impact
  need hardware validation. The timeout removal also applies to Connect sessions.
- The decoder currently uses Linux FFmpeg `.so` names. macOS receiver support is
  unverified. Native libdatachannel callback owners are retained until helper exit
  to avoid binding teardown races; the helper uses `os._exit` after cleanup.
- Helper startup/negotiation can outlast the three-second shutdown grace period;
  Cabana then kills it. Failed device startup can leave IsLiveStreaming set until
  teardown/restart. No automatic startup retry is implemented.

## After the hackathon

- [ ] Validate real device + account signaling, TURN-only cellular networks, ignition
  on/off transitions, sessions longer than five minutes, and single-viewer takeover.
- [ ] Measure onroad CPU/thermal/encoder impact and long-session memory/bandwidth.
- [ ] Add reconnect/backoff, connection state, stale-frame clearing, cancellation
  during negotiation, and actionable auth/unsupported-device errors.
- [ ] Separate CAN from control traffic; add protocol/version negotiation, sequence
  numbers, gap indicators, batching, and explicit receiver backpressure.
- [ ] Preserve capture timestamps for video/CAN alignment; add a rolling video
  buffer and recording before presenting video as synchronized playback.
- [ ] Add camera switching and quality controls; harden keyframe recovery and
  resolution changes under packet loss.
- [ ] Make encoding demand-driven onroad and add explicit idle/session policy,
  with deterministic cleanup when startup or signaling fails.
- [ ] Package the helper/interpreter dependencies, support macOS, and replace the
  native-binding exit workaround with reliable library lifecycle management.
- [ ] Add sustained hardware/network fault tests and automated Cabana UI coverage
  for connecting, replacing a stream, pausing CAN, and closing during negotiation.
