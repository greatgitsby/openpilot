#!/usr/bin/env python3
"""Run Qwen3-VL on fresh road-camera frames using a resident chestnut GPU graph."""

import os
import time
from pathlib import Path

import numpy as np

from openpilot.cereal.visionipc import VisionStreamType
from openpilot.common.swaglog import cloudlog
from msgq.visionipc import VisionIpcClient, VisionBuf


MODEL_DIR = Path(os.getenv("QWEN3_VL_MODEL_DIR", "/data/models/qwen3vl"))
TEXT_MODEL = MODEL_DIR / "Qwen3VL-2B-Instruct-Q4_K_M.gguf"
VISION_MODEL = MODEL_DIR / "mmproj-Qwen3VL-2B-Instruct-Q8_0.gguf"
# Keep the hello-world path intentionally small. Qwen's patch/merge factor is 32,
# so this produces a 2x2 (four-token) visual grid from the live road frame.
IMAGE_HEIGHT, IMAGE_WIDTH = 64, 64
PROMPT = "Reply with exactly: Hello world!"


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
  while not (streams := VisionIpcClient.available_streams("camerad", block=False)):
    time.sleep(0.1)
  stream = VisionStreamType.VISION_STREAM_NARROW_ROAD if VisionStreamType.VISION_STREAM_NARROW_ROAD in streams \
    else VisionStreamType.VISION_STREAM_WIDE_ROAD
  client = VisionIpcClient("camerad", stream, True)
  while not client.connect(False):
    time.sleep(0.1)
  cloudlog.warning(f"gemmad connected to {stream}: {client.width}x{client.height}")
  return client


def main() -> None:
  missing = [str(path) for path in (TEXT_MODEL, VISION_MODEL) if not path.is_file()]
  if missing:
    raise FileNotFoundError(f"missing Qwen3-VL model file(s): {', '.join(missing)}")

  client = connect_road_camera()
  while (frame := client.recv()) is None:
    pass
  image = prepare_image(frame)

  # tinygrad reads its default device while importing, so configure chestnut first.
  os.environ["DEV"] = "USB+AMD:LLVM"
  os.environ["GMMU"] = "0"
  os.environ.setdefault("HCQDEV_WAIT_TIMEOUT_MS", "3000")
  from tinygrad import Tensor
  from tinygrad.llm.cli import SimpleTokenizer
  from tinygrad.llm.model import Transformer
  from tinygrad.llm.qwen3vl import Qwen3Vision, Qwen3VLRunner, materialize_weights

  cloudlog.warning("gemmad loading Qwen3-VL")
  model, kv = Transformer.from_gguf(TEXT_MODEL, max_context=128)
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

  runner = Qwen3VLRunner(model, vision, tokens, (len(prefix), len(prefix)+image_tokens), grid, max_new_tokens=16)
  for i in range(2):
    cloudlog.warning(f"gemmad graph warmup {i+1}/2")
    runner(Tensor(image).realize()).tolist()
  cloudlog.warning("gemmad ready for fresh road frames")
  previous_frame = None
  while True:
    if (frame := client.recv()) is None:
      continue
    start = time.monotonic_ns()
    frame_id = client.frame_id
    capture_ns = client.timestamp_eof
    skipped = 0 if previous_frame is None else max(0, frame_id-previous_frame-1)
    previous_frame = frame_id
    result = runner(Tensor(prepare_image(frame)).realize()).tolist()[0]
    end = next((i for i, token in enumerate(result) if tokenizer.is_end(token)), len(result))
    response = tokenizer.decode(result[:end])
    print(f"gemmad Qwen3-VL frame={frame_id}: {response}", flush=True)
    elapsed_ms = (time.monotonic_ns()-start)/1e6
    capture_ms = (time.clock_gettime_ns(time.CLOCK_BOOTTIME)-capture_ns)/1e6 if capture_ns else None
    complete = end < len(result)
    meets_deadline = complete and capture_ms is not None and 0 <= capture_ms < 200
    print(f"gemmad receipt_to_stdout_ms={elapsed_ms:.2f} capture_to_stdout_ms={capture_ms} " +
          f"complete={complete} skipped_frames={skipped} meets_200ms={meets_deadline}", flush=True)


if __name__ == "__main__":
  main()
