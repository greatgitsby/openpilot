#!/usr/bin/env python3
"""Run a one-shot Qwen3-VL road-camera prompt on the chestnut eGPU."""

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
IMAGE_HEIGHT, IMAGE_WIDTH = 256, 416


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
  mean = np.array([0.48145466, 0.45782750, 0.40821073], dtype=np.float32)
  std = np.array([0.26862954, 0.26130258, 0.27577711], dtype=np.float32)
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
  from tinygrad.llm.qwen3vl import Qwen3Vision

  cloudlog.warning("gemmad loading Qwen3-VL")
  model, kv = Transformer.from_gguf(TEXT_MODEL, max_context=512)
  vision = Qwen3Vision.from_gguf(VISION_MODEL)
  tokenizer = SimpleTokenizer.from_gguf_kv(kv)

  # USB+AMD resolves to the underlying AMD compute device; use that canonical default
  # so camera inputs and GGUF weights share one tinygrad device.
  image_embeds, deepstack, grid = vision(Tensor(image))
  image_tokens = image_embeds.shape[0]
  prefix = tokenizer.encode("<|im_start|>user\n<|vision_start|>")
  suffix = tokenizer.encode(
    "<|vision_end|>\nSay hello and briefly acknowledge that you received this road camera frame." +
    "<|im_end|>\n<|im_start|>assistant\n"
  )
  image_token = tokenizer._special_tokens["<|image_pad|>"]
  tokens = prefix + [image_token] * image_tokens + suffix

  print("gemmad Qwen3-VL response: ", end="", flush=True)
  decoder = tokenizer.stream_decoder()
  for token in model.generate_vision(tokens, (len(prefix), len(prefix)+image_tokens), image_embeds, deepstack, grid):
    if tokenizer.is_end(token):
      break
    print(decoder(token), end="", flush=True)
  print(decoder(), flush=True)

  # Keep the managed process alive after the one-shot hello-world inference.
  while True:
    client.recv()


if __name__ == "__main__":
  main()
