"""Measure fresh camerad frame to complete Qwen3-VL response, including USB copies.

Run while gemmad is stopped (chestnut permits one owner):
  python -m openpilot.selfdrive.modeld.benchmark_qwen3vl --runs 10
Compilation and two graph warmups are reported separately from measured frames.
"""
import argparse
import json
import os
import time

os.environ['DEV'] = 'USB+AMD:LLVM'
os.environ['GMMU'] = '0'
os.environ.setdefault('HCQDEV_WAIT_TIMEOUT_MS', '3000')

from tinygrad import Tensor, Device
from tinygrad.llm.cli import SimpleTokenizer
from tinygrad.llm.model import Transformer
from tinygrad.llm.qwen3vl import Qwen3Vision, Qwen3VLRunner, materialize_weights
from openpilot.selfdrive.modeld.gemmad import (TEXT_MODEL, VISION_MODEL, PROMPT, DIRECTIONS, MAX_CONTEXT, MAX_TOKENS,
                                             connect_road_camera, prepare_image, format_plan)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--runs', type=int, default=10)
  parser.add_argument('--tokens', type=int, choices=[MAX_TOKENS], default=MAX_TOKENS)
  parser.add_argument('--fp16-compute', action='store_true', help='FP16 matrix inputs with float32 accumulation')
  args = parser.parse_args()
  if args.runs < 1:
    parser.error('runs must be positive')
  start = time.perf_counter()
  print('loading text weights', flush=True)
  model, kv = Transformer.from_gguf(TEXT_MODEL, max_context=MAX_CONTEXT)
  materialize_weights(model, fp16_compute=args.fp16_compute)
  print(f'device={Device.DEFAULT} arch={Device[Device.DEFAULT].arch} fp16_compute={args.fp16_compute}', flush=True)
  print(f'text resident after {time.perf_counter()-start:.1f}s', flush=True)
  vision = Qwen3Vision.from_gguf(VISION_MODEL)
  materialize_weights(vision, fp16_compute=args.fp16_compute)
  print(f'all weights resident after {time.perf_counter()-start:.1f}s', flush=True)
  tokenizer = SimpleTokenizer.from_gguf_kv(kv)
  client = connect_road_camera()
  while (frame := client.recv()) is None:
    pass
  image = prepare_image(frame)
  grid = (1, image.shape[2]//16, image.shape[3]//16)
  count = grid[1]*grid[2]//4
  prefix = tokenizer.encode('<|im_start|>user\n<|vision_start|>')
  suffix = tokenizer.encode(f'<|vision_end|>\n{PROMPT}<|im_end|>\n<|im_start|>assistant\n')
  tokens = prefix + [tokenizer._special_tokens['<|image_pad|>']]*count + suffix
  encoded = [tokenizer.encode(letter) for letter in DIRECTIONS]
  if any(len(ids) != 1 for ids in encoded):
    raise ValueError('direction letters must be single tokens')
  runner = Qwen3VLRunner(model, vision, tokens, (len(prefix), len(prefix)+count), grid, args.tokens,
                        allowed_tokens=[ids[0] for ids in encoded])
  for i in range(2):
    warm = time.perf_counter()
    print(f'warmup {i+1} starting', flush=True)
    result = runner(Tensor(image).realize()).tolist()[0]
    print(f'warmup {i+1}: {time.perf_counter()-warm:.3f}s, {tokenizer.decode(result)!r}', flush=True)
  Device[Device.DEFAULT].synchronize()
  measurements = []
  capture_measurements, complete_responses = [], []
  previous_frame = None
  for _ in range(args.runs):
    while (frame := client.recv()) is None:
      pass
    frame_id = client.frame_id
    capture_ns = client.timestamp_eof
    skipped = 0 if previous_frame is None else max(0, frame_id-previous_frame-1)
    previous_frame = frame_id
    start_ns = time.monotonic_ns()
    result = runner(Tensor(prepare_image(frame)).realize()).tolist()[0]
    end = next((j for j, token in enumerate(result) if tokenizer.is_end(token)), len(result))
    response = json.dumps(format_plan(result, dict(zip([ids[0] for ids in encoded], DIRECTIONS, strict=True))))
    print(f'gemmad response frame={frame_id}: {response}', flush=True)
    elapsed = (time.monotonic_ns()-start_ns)/1e6
    capture_ms = (time.clock_gettime_ns(time.CLOCK_BOOTTIME)-capture_ns)/1e6 if capture_ns else None
    complete = len(result) == MAX_TOKENS
    measurements.append(elapsed)
    capture_measurements.append(capture_ms)
    complete_responses.append(complete)
    print(json.dumps({'frame_id': frame_id, 'receipt_to_stdout_ms': elapsed, 'capture_to_stdout_ms': capture_ms,
                      'tokens_budget': args.tokens, 'tokens_before_eos': end, 'complete': complete, 'skipped_frames': skipped,
                      'meets_200ms': complete and capture_ms is not None and 0 <= capture_ms < 200}), flush=True)
  print(json.dumps({'min_ms': min(measurements), 'max_ms': max(measurements),
                    'mean_ms': sum(measurements)/len(measurements), 'all_complete': all(complete_responses),
                    'all_under_200ms': all(complete_responses) and all(t is not None and 0 <= t < 200
                                                                 for t in capture_measurements)}), flush=True)


if __name__ == '__main__':
  main()
