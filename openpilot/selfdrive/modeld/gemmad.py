#!/usr/bin/env python3
"""Run Qwen3-VL on fresh road-camera frames using a resident chestnut GPU graph."""

import os
import time
import argparse
import hashlib
import json
import sys
import contextlib
from pathlib import Path

import numpy as np

from openpilot.cereal.visionipc import VisionStreamType
from openpilot.common.swaglog import cloudlog
from msgq.visionipc import VisionIpcClient, VisionBuf


MODEL_DIR = Path(os.getenv("QWEN3_VL_MODEL_DIR", "/data/models/qwen3vl"))
TEXT_MODEL = MODEL_DIR / "Qwen3VL-2B-Instruct-Q4_K_M.gguf"
VISION_MODEL = MODEL_DIR / "mmproj-Qwen3VL-2B-Instruct-Q8_0.gguf"
# Forty visual tokens, preserving more scene detail than the hello-world demo.
IMAGE_HEIGHT, IMAGE_WIDTH = 160, 256
PROMPT = ("You are viewing the robot's front wide camera. Navigate through the scene without hitting people or obstacles. Steer clear! " +
          "Choose W=forward only when the path directly ahead is clear. Otherwise choose A=turn left or D=turn right toward clear space. " +
          "S=backward; rear clearance is unknown from this image. Avoid moving toward nearby people, furniture, walls, or other obstacles. " +
          "Reply with exactly one letter: W, A, S, or D. No explanation.")
MAX_TOKENS = 1
DIRECTIONS = ("W", "A", "S", "D")
MAX_CONTEXT = 256


def extract_rgb(buf: VisionBuf) -> np.ndarray:
  """Convert a camerad NV12 buffer to RGB and resize it for Qwen3-VL."""
  y = np.frombuffer(buf.data, dtype=np.uint8, count=buf.uv_offset).reshape(-1, buf.stride)[:buf.height, :buf.width]
  uv_height = (buf.height // 2 + 15) // 16 * 16
  uv = np.frombuffer(buf.data, dtype=np.uint8, count=buf.stride * uv_height, offset=buf.uv_offset).reshape(-1, buf.stride)
  u, v = uv[:buf.height//2, :buf.width:2], uv[:buf.height//2, 1:buf.width:2]

  # Resize the planes before conversion to keep host memory and upload time small.
  yi = np.linspace(0, buf.height-1, IMAGE_HEIGHT).astype(np.int32)
  xi = np.linspace(0, buf.width-1, IMAGE_WIDTH).astype(np.int32)
  uvi = np.minimum(yi // 2, u.shape[0]-1)
  uvj = np.minimum(xi // 2, u.shape[1]-1)
  yf = y[yi[:, None], xi].astype(np.float32)
  uf = u[uvi[:, None], uvj].astype(np.float32) - 128.0
  vf = v[uvi[:, None], uvj].astype(np.float32) - 128.0
  return np.stack((yf + 1.13983*vf, yf - 0.39465*uf - 0.58060*vf, yf + 2.03211*uf), axis=-1).clip(0, 255)


def prepare_image(buf: VisionBuf) -> np.ndarray:
  image = extract_rgb(buf) / 255.0
  mean = np.array([0.5, 0.5, 0.5], dtype=np.float32)
  std = np.array([0.5, 0.5, 0.5], dtype=np.float32)
  return ((image - mean) / std).transpose(2, 0, 1)[None].astype(np.float16)


def connect_road_camera() -> VisionIpcClient:
  stream = VisionStreamType.VISION_STREAM_WIDE_ROAD
  # Never silently substitute narrow: the Body's narrow view can show mostly floor.
  while stream not in VisionIpcClient.available_streams("camerad", block=False):
    time.sleep(0.1)
  client = VisionIpcClient("camerad", stream, True)
  while not client.connect(False):
    time.sleep(0.1)
  cloudlog.warning(f"gemmad connected to wide road ({stream}): {client.width}x{client.height}")
  return client


def build_program():
  from tinygrad import Tensor
  from tinygrad.llm.cli import SimpleTokenizer
  from tinygrad.llm.model import Transformer
  from tinygrad.llm.qwen3vl import Qwen3Vision, Qwen3VLRunner, materialize_weights

  cloudlog.warning("gemmad loading Qwen3-VL")
  model, kv = Transformer.from_gguf(TEXT_MODEL, max_context=MAX_CONTEXT)
  materialize_weights(model)
  vision = Qwen3Vision.from_gguf(VISION_MODEL)
  materialize_weights(vision)
  tokenizer = SimpleTokenizer.from_gguf_kv(kv)

  grid = (1, IMAGE_HEIGHT//16, IMAGE_WIDTH//16)
  image_tokens = grid[1]*grid[2]//4
  prefix = tokenizer.encode("<|im_start|>user\n<|vision_start|>")
  suffix = tokenizer.encode(
    f"<|vision_end|>\n{PROMPT}<|im_end|>\n<|im_start|>assistant\n"
  )
  image_token = tokenizer._special_tokens["<|image_pad|>"]
  tokens = prefix + [image_token] * image_tokens + suffix

  encoded = [tokenizer.encode(letter) for letter in DIRECTIONS]
  if any(len(ids) != 1 for ids in encoded):
    raise ValueError("direction letters must each encode to one token")
  allowed_tokens = [ids[0] for ids in encoded]
  runner = Qwen3VLRunner(model, vision, tokens, (len(prefix), len(prefix)+image_tokens), grid,
                        max_new_tokens=MAX_TOKENS, allowed_tokens=allowed_tokens)
  # Cache construction never needs or persists a real camera image.
  image = np.zeros((1, 3, IMAGE_HEIGHT, IMAGE_WIDTH), dtype=np.float16)
  for i in range(2):
    cloudlog.warning(f"gemmad graph warmup {i+1}/2")
    runner(Tensor(image).realize()).tolist()
  return {"run": runner.jit, "tokenizer": tokenizer, "directions": dict(zip(allowed_tokens, DIRECTIONS, strict=True))}


def cache_path(arch: str) -> Path:
  import tinygrad
  root = Path(tinygrad.__file__).parent
  digest = hashlib.sha256()
  for source in sorted(root.rglob("*.py")):
    digest.update(str(source.relative_to(root)).encode())
    digest.update(source.read_bytes())
  settings = {"version": 2, "arch": arch, "python": list(sys.version_info[:2]), "prompt": PROMPT,
              "shape": [IMAGE_HEIGHT, IMAGE_WIDTH], "tokens": MAX_TOKENS, "context": MAX_CONTEXT, "directions": DIRECTIONS,
              "models": [(str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in (TEXT_MODEL, VISION_MODEL)],
              "env": {k: os.getenv(k) for k in ("DEV", "GMMU", "TC_OPT", "TC_MIN_GLOBALS", "FLOAT16", "HCQ2")}}
  digest.update(json.dumps(settings, sort_keys=True).encode())
  return MODEL_DIR / "compiled" / digest.hexdigest()


def run(output) -> None:
  startup = time.monotonic()
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--prepare-cache", action="store_true", help="build/load the local artifact without connecting to camerad")
  args = parser.parse_args()
  missing = [str(path) for path in (TEXT_MODEL, VISION_MODEL) if not path.is_file()]
  if missing:
    raise FileNotFoundError(f"missing Qwen3-VL model file(s): {', '.join(missing)}")
  # tinygrad reads its default device while importing, so configure chestnut first.
  os.environ["DEV"] = "USB+AMD:LLVM"
  os.environ["GMMU"] = "0"
  os.environ.setdefault("HCQDEV_WAIT_TIMEOUT_MS", "3000")
  from tinygrad import Tensor, Device
  from tinygrad.llm.artifact import load_artifact, save_artifact
  imported = time.monotonic()
  device = Device[Device.DEFAULT]
  initialized = time.monotonic()
  path = cache_path(device.arch)
  print(f"gemmad startup imports_s={imported-startup:.3f} gpu_init_s={initialized-imported:.3f} " +
        f"cache_key_s={time.monotonic()-initialized:.3f}", flush=True)
  if path.exists():
    program, timings = load_artifact(path)
    print(f"gemmad cache hit {path.name} {json.dumps(timings)}", flush=True)
  else:
    cloudlog.warning(f"gemmad cache miss {path.name}; preparing once")
    build_start = time.monotonic()
    program = build_program()
    built = time.monotonic()
    save_artifact(program, path)
    print(f"gemmad cache saved build_s={built-build_start:.3f} save_s={time.monotonic()-built:.3f}", flush=True)
  runner, directions = program["run"], program["directions"]
  link_start = time.monotonic()
  _ = runner.captured.linear
  print(f"gemmad startup link_s={time.monotonic()-link_start:.3f} ready_s={time.monotonic()-startup:.3f}", flush=True)
  if args.prepare_cache:
    result = runner(Tensor(np.zeros((1, 3, IMAGE_HEIGHT, IMAGE_WIDTH), dtype=np.float16)).realize()).tolist()[0]
    if len(result) != 1 or result[0] not in directions:
      raise ValueError(f"invalid direction result: {result}")
    print(f"gemmad cache smoke direction: {directions[result[0]]}", flush=True)
    print(f"gemmad startup first_response_s={time.monotonic()-startup:.3f}", flush=True)
    return
  client = connect_road_camera()
  cloudlog.warning("gemmad ready for fresh road frames")
  previous_frame = None
  first_response = True
  while True:
    if (frame := client.recv()) is None:
      continue
    start = time.monotonic_ns()
    frame_id = client.frame_id
    capture_ns = client.timestamp_eof
    skipped = 0 if previous_frame is None else max(0, frame_id-previous_frame-1)
    previous_frame = frame_id
    result = runner(Tensor(prepare_image(frame)).realize()).tolist()[0]
    if len(result) != 1 or result[0] not in directions:
      raise ValueError(f"invalid direction result: {result}")
    print(directions[result[0]], file=output, flush=True)
    if first_response:
      print(f"gemmad startup first_response_s={time.monotonic()-startup:.3f}", flush=True)
      first_response = False
    elapsed_ms = (time.monotonic_ns()-start)/1e6
    capture_ms = (time.clock_gettime_ns(time.CLOCK_BOOTTIME)-capture_ns)/1e6 if capture_ns else None
    meets_deadline = capture_ms is not None and 0 <= capture_ms < 200
    print(f"gemmad frame={frame_id} receipt_to_stdout_ms={elapsed_ms:.2f} capture_to_stdout_ms={capture_ms} " +
          f"skipped_frames={skipped} meets_200ms={meets_deadline}", flush=True)


def main() -> None:
  # All library/startup diagnostics go to stderr; stdout is the advisory letter stream only.
  output = sys.stdout
  with contextlib.redirect_stdout(sys.stderr):
    run(output)


if __name__ == "__main__":
  main()
