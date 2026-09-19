# Qwen3-VL five-second plan experiment

## Current output

Each latest wide-camera frame produces an advisory five-second plan, one JSON
array per stdout line, for example:

```json
[{"command":"A","seconds":1},{"command":"W","seconds":4}]
```

The VLM generates five constrained direction tokens, one per one-second slot.
Adjacent identical slots are merged; durations are positive whole seconds and
always total five. W=forward, A=left, S=backward, D=right. There is no stop
command. Each new plan replaces the preceding suggestion; there is no command
queue, timer, or actuation. A single image cannot verify rear clearance or
predict five seconds of motion. Do not execute these unvalidated plans blindly.
Diagnostics and frame age remain on stderr. The new five-token prompt requires
a new startup cache; timings below are historical single-letter measurements.

## Historical single-letter output

The previous `gemmad` consumes the latest **wide** road-camera frame (conflated VisionIPC),
resizes it to 256x160, and asks the VLM which direction leads through visible
clear space while avoiding obstacles. It emits exactly one uppercase letter
per inference, followed by a newline, to **stdout**:

- `W`: forward
- `A`: turn left
- `S`: backward
- `D`: turn right

It waits for the wide stream rather than substituting the narrow camera, which
can see mostly floor on the Body. The prompt explicitly requests navigating
without hitting people or obstacles, choosing forward only when directly ahead
is clear, and turning toward clear space otherwise. This is an instruction to
the VLM, not a verified collision-avoidance guarantee.

Decoding is constrained to the four corresponding vocabulary tokens, rather
than parsing a free-form explanation. Each letter is a complete one-token
response, so EOS is not required. Startup and frame diagnostics go to stderr.
There are no commands, CAN messages, controller inputs, or actuation connections.
These outputs are unvalidated advisory suggestions: a front image cannot show
rear clearance, and this four-letter alphabet has no stop/abstain action. Do not
wire it directly to actuation. Slow inference drops intervening camera frames;
the next iteration receives the latest available frame rather than a backlog.

The new prompt, image size, constrained vocabulary, and token budget invalidate
the old hello-world cache. Startup preparation must run once for this graph.

### Direction-stream device validation

On the comma four/tinychestnut, eight live-camera stdout records passed an
exact `W\n` / `A\n` / `S\n` / `D\n` check (all eight were `W` in the observed
scene). This validates the stream format and camera integration, not navigation
correctness. The output projection uses only the four allowed vocabulary rows;
the initial full-vocabulary projection exhausted GPU memory during capture.

With 256x160 input, warm receipt-to-stdout latency was **3623–3672 ms** and
capture-to-stdout latency **3693–3736 ms**, skipping 72–73 frames per result.
The first live inference took 4440 ms. **The 200 ms target remains unmet.**

The new artifact contains 3,673,788,944 buffer bytes. A fresh cached process
measured GPU initialization 0.985 s, upload 40.970 s, deserialization 1.193 s,
linking 0.795 s, ready at 45.343 s, and first live response at 49.811 s.
One-time preparation took 441.513 s plus 73.886 s to save the artifact.

## Historical hello-world baseline

`gemmad` runs only with comma body. It reads the latest road-camera frame,
resizes it to 64x64 RGB, and asks Qwen3-VL-2B-Instruct to reply `Hello world!`.
It only prints text; its output is not connected to actuation.

The language and vision GGUF weights are decoded once into chestnut VRAM.
After two warmups, tinygrad replays the image encoder, prompt prefill and a
16-token greedy decode without a host read for every token. Output after the
first end-of-response token is discarded. A response without an end token
within the budget is reported as incomplete.

This is a latency experiment, not a validated perception model. The 64x64
input is substantially smaller than the model's normal image preprocessing.
Weights must already exist in `/data/models/qwen3vl`:

- `Qwen3VL-2B-Instruct-Q4_K_M.gguf`
- `mmproj-Qwen3VL-2B-Instruct-Q8_0.gguf`

### Historical acceptance criteria and measurement

The requested target is a **complete response of up to 16 tokens within
200 ms for each new camera frame**, not time to first token. Startup/compilation
is reported separately. Runtime includes image preprocessing, USB transfers,
vision inference, all 16 decode steps, text decoding and a flushed stdout write.
`capture_to_stdout_ms` uses camerad's end-of-frame timestamp and CLOCK_BOOTTIME;
`receipt_to_stdout_ms` starts at VisionIPC receipt. Both are reported.
An incomplete response or missing capture timestamp never passes the deadline.

The current latest-frame subscription can skip frames when inference is slower
than the camera. `skipped_frames` makes that visible; meeting the latency bound
on selected frames alone would not establish the each-frame requirement.

On the comma four/tinychestnut, the first resident-graph baseline measured
**1414–1443 ms** from frame receipt through printing (five frames, mean 1428 ms).
That baseline used `Say hello.` and exhausted the 16-token budget without an end
token. It establishes execution and a latency failure, not complete-response
acceptance. The stricter prompt and completion/capture checks were added after
that run. **The 200 ms target has not been achieved.**

The FP16-input/FP32-accumulation experiment with `TC_OPT=2` was slightly slower
(about 1493–1519 ms per frame). It remains available in the benchmark but is
not enabled in the managed daemon.

After deployment, the exact-greeting prompt produced complete `Hello world!`
responses. Example live samples measured 1593–1630 ms from receipt and
1625–1695 ms from capture, skipping 31–32 intervening frames. This confirms
complete-response execution but fails both the latency and each-frame targets.

## Benchmark the current direction stream

Do not run the benchmark while gemmad or another process owns chestnut. On a
test device with camerad running and gemmad stopped:

```sh
python -m openpilot.selfdrive.modeld.benchmark_qwen3vl --runs 10
TC_OPT=2 python -m openpilot.selfdrive.modeld.benchmark_qwen3vl --runs 10 --fp16-compute
```

These are two different matrix execution paths. The benchmark prints warmup
times, each response, per-frame timing/completion records and a summary.
It now uses the navigation prompt and constrained one-token response, matching
the daemon; the 16-token timings above describe the earlier hello-world graph.
CPU regression tests live in the tinygrad fork at `test/unit/test_qwen3vl.py`.

## Startup cache

`gemmad --prepare-cache` can prepare the program without camerad. The first run
decodes the weights, captures the graph using a synthetic image, and publishes
an immutable artifact under `/data/models/qwen3vl/compiled/<fingerprint>/`.
Normal startup uses the same cache automatically. No real camera image is used
to build it. Run preparation only when no other process owns chestnut.

```sh
python -m openpilot.selfdrive.modeld.gemmad --prepare-cache
```

The fingerprint includes tinygrad Python sources, model paths/sizes/mtimes,
GPU architecture, prompt, image size, token budget and relevant runtime options.
Changed inputs generate a different artifact; old artifacts are not deleted.
Artifacts contain executable Python pickle data and must only come from this
trusted local build. Publication is atomic, and truncated files are rejected.

Cached startup separately reports imports, GPU initialization, cache fingerprint,
buffer upload, graph deserialization, runtime linking, and time to first output
(from entry to `main`). Cache hits do not parse GGUF, construct the model or
perform capture warmups. GPU initialization and the VRAM upload remain necessary
in a new process. The predecoded cache occupies several GB on disk.

Historical hello-world measured fresh managed-process startup (disk artifact present;
not a device reboot, and excluding openpilot's separate build step):

| Phase | Seconds |
| --- | ---: |
| tinygrad imports | 0.405 |
| GPU initialization | 0.699 |
| Cache fingerprint | 0.126 |
| Upload 4.272 GB | 46.543 |
| Deserialize program | 2.248 |
| Runtime linking | 5.832 |
| Ready, cumulative | 55.992 |
| First complete live-camera response, cumulative | 58.456 |

The original cached linker took 20.1 seconds. Profiling found about 47,700 tiny
USB writes. The tinygrad fork now batches link-time patches in a host shadow,
but only for freshly allocated command/argument buffers, never live rings or
signals. Standalone linking dropped to 4.7 seconds, with all 16 output token IDs
unchanged. The first artifact was explicitly validated and reused for this
linker-only change; unknown future source changes still invalidate the cache.

The one-time build took 626.6 seconds, followed by a 97.0-second cache save.
The artifact contains 4,271,811,328 buffer bytes and 7,723,471 program bytes.
The latest managed run continued to print complete greetings at roughly
1.6 seconds per frame; startup caching does not satisfy the 200 ms frame target.
