#!/usr/bin/env python3
"""Fetch a small, cached OpenStreetMap road layer for the visible route area."""

import hashlib
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request


def roads(request):
  bounds = request['bounds']
  if len(bounds) != 4 or not (-85 <= bounds[0] < bounds[2] <= 85 and -180 <= bounds[1] < bounds[3] <= 180):
    raise ValueError('Invalid map bounds')
  if bounds[2] - bounds[0] > 0.2 or bounds[3] - bounds[1] > 0.2:
    raise ValueError('Zoom in to load streets')
  cache = Path(request['cache'])
  cache.mkdir(parents=True, exist_ok=True)
  target = cache / (hashlib.sha256(json.dumps(bounds).encode()).hexdigest() + '.json')
  if target.exists():
    return json.loads(target.read_text())
  bbox = ','.join(str(value) for value in bounds)
  query = f'[out:json][timeout:8];way["highway"]({bbox});out geom;'
  body = urllib.parse.urlencode({'data': query}).encode()
  req = urllib.request.Request('https://overpass-api.de/api/interpreter', body, headers={'User-Agent': 'Cabana route analysis'})
  with urllib.request.urlopen(req, timeout=10) as response:
    raw = response.read(16 * 1024 * 1024)
  elements = json.loads(raw)['elements']
  result = {'roads': [[[point['lon'], point['lat']] for point in way.get('geometry', [])] for way in elements]}
  temporary = target.with_suffix('.tmp')
  temporary.write_text(json.dumps(result))
  temporary.replace(target)
  return result


if __name__ == '__main__':
  try:
    with open(sys.argv[1]) as f:
      result = roads(json.load(f))
  except Exception as exc:
    result = {'error': str(exc)}
  with open(sys.argv[2], 'w') as f:
    json.dump(result, f)
