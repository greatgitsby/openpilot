# Qwen3-VL hello-world experiment

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

## Acceptance criteria and measurement

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

## Reproduce

Do not run the benchmark while gemmad or another process owns chestnut. On a
test device with camerad running and gemmad stopped:

```sh
python -m openpilot.selfdrive.modeld.benchmark_qwen3vl --runs 10
TC_OPT=2 python -m openpilot.selfdrive.modeld.benchmark_qwen3vl --runs 10 --fp16-compute
```

These are two different matrix execution paths. The benchmark prints warmup
times, each response, per-frame timing/completion records and a summary.
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
