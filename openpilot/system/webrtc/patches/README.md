# libdatachannel Python binding workaround

`libdatachannel-py==2026.1.0.dev2` holds Python's GIL while sending data and
video. A receive callback can hold the native transport lock while waiting for
the GIL, deadlocking a simultaneous send. CAN traffic makes this reproducible
when connecting Cabana repeatedly. `libdatachannel-gil.patch` releases the GIL
around native sends, closes, and video feedback requests.

Build and install on the target platform (Python 3.12):

```sh
git clone --branch 2026.1.0.dev2 https://github.com/shiguredo/libdatachannel-py.git
cd libdatachannel-py
# Tag commit: 989d29a32968046a002b5b9deb7a00f5012c530c
git apply /path/to/openpilot/openpilot/system/webrtc/patches/libdatachannel-gil.patch
CMAKE_BUILD_PARALLEL_LEVEL=2 uv build --wheel --python python3
uv pip install --python /path/to/environment/bin/python --reinstall dist/*.whl
```

On AGNOS, updating `/usr/local/venv` requires temporarily remounting `/` writable
and running the install as root. Restore the read-only mount after installation.

Apply this to the device and the Cabana host. The wheel retains the upstream
version; reinstalling the upstream wheel removes the fix. This patch needs to
be incorporated into the dependency before the workaround can be removed.

## Cabana TURN transports

The upstream wheel uses libjuice, which supports TURN over UDP only and ignores
the API's TCP/TLS relay servers. On networks where UDP TURN gets no response,
gathering takes about 23.5 seconds and yields no relay candidate.

On Linux Cabana hosts, also apply `libdatachannel-turn.patch` before building to
use libnice, which supports TCP/TLS TURN. Install the libnice development files
and pkg-config first (`libnice` on Arch, `libnice-dev` and `pkg-config` on Ubuntu).
Use a fresh source checkout: the build reuses libraries already in `_deps` even
when the ICE backend changes. The resulting wheel needs libnice at runtime and
must be built for the host distribution; do not copy it onto AGNOS.

```sh
git apply /path/to/openpilot/openpilot/system/webrtc/patches/libdatachannel-turn.patch
```

Cabana sends its offer after the first relay candidate, completed gathering, or
an eight-second deadline, matching Connect. Startup stage timings, including
first CAN and decoded video, are written to stderr.

From the openpilot checkout, verify the installed binding with:

```sh
python -m unittest openpilot.tools.cabana.tests.test_native_webrtc.TestNativeWebRTC.test_send_during_keyframe_callback
```

The test sends a CAN message while a native keyframe callback is active. It runs
in a subprocess with a deadline so the original deadlock fails the test instead
of hanging the test runner.

On the Cabana host, run the entire `test_native_webrtc` module as well. Its local
TCP TURN listener checks that the installed backend sends an Allocate request;
this catches accidentally reinstalling the UDP-only upstream wheel.

The same release also crashes when `DataChannel.buffered_amount()` is called.
The CAN bridge avoids that binding. Compressed CAN batches use a bounded window
of bytes acknowledged after Cabana writes them to its reader, so buffered sends
that are draining normally do not accumulate a false backlog.
