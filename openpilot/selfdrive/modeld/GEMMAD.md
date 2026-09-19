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
