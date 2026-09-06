#!/usr/bin/env python3
"""Evaluate an analysis formula in a disposable process, using a JSON interchange."""

import json
import math
import sys
import textwrap

import numpy as np


def evaluate(request):
  channels = {name: np.asarray(points, dtype=float).reshape((-1, 2)) for name, points in request['channels'].items()}
  formula = request['formula']
  source = formula.get('linked_source', '')
  reference = channels[source][:, 0] if source else None

  def times(name):
    return channels[name][:, 0]

  def values(name):
    return channels[name][:, 1]

  namespace = {'np': np, 'numpy': np, 'math': math, 't': times, 'v': values}
  if reference is not None:
    namespace.update(time=reference, value=values(source))
  for index, name in enumerate(formula.get('additional_sources', []), 1):
    if reference is None:
      raise ValueError('Additional sources require an input series')
    points = channels[name]
    if len(points) == 0:
      raise ValueError(f'Additional source is empty: {name}')
    positions = np.searchsorted(points[:, 0], reference, side='right') - 1
    aligned = points[np.clip(positions, 0, len(points) - 1), 1].copy()
    aligned[positions < 0] = np.nan
    namespace[f'v{index}'] = aligned
  exec(compile(formula.get('globals_code', ''), '<analysis globals>', 'exec'), namespace)
  body = formula.get('function_code', '').strip()
  if not body:
    raise ValueError('Enter an expression or a function body')
  try:
    expression = compile(body, '<analysis expression>', 'eval')
  except SyntaxError:
    exec(compile('def calculate():\n' + textwrap.indent(body, '  '), '<analysis function>', 'exec'), namespace)
    result = namespace['calculate']()
  else:
    result = eval(expression, namespace)
  if isinstance(result, tuple) and len(result) == 2:
    output_time, output_value = result
  else:
    if reference is None:
      raise ValueError('Choose an input series or return (times, values)')
    output_time, output_value = reference, result
  output_time = np.asarray(output_time, dtype=float)
  output_value = np.asarray(output_value, dtype=float)
  if output_value.ndim == 0:
    output_value = np.full(output_time.shape, output_value)
  if output_time.ndim != 1 or output_time.shape != output_value.shape or output_time.size == 0:
    raise ValueError('Result must be nonempty, equally sized time and value vectors')
  if output_time.size > 10_000_000:
    raise ValueError('Result exceeds ten million samples')
  finite = np.isfinite(output_time) & np.isfinite(output_value)
  result = np.column_stack((output_time[finite], output_value[finite]))
  result = result[np.argsort(result[:, 0], kind='stable')]
  if not len(result):
    raise ValueError('Result contains no finite samples')
  return result.tolist()


if __name__ == '__main__':
  try:
    with open(sys.argv[1]) as f:
      request = json.load(f)
    if 'formulas' in request:
      result = {'results': {}, 'errors': {}}
      pending = list(request['formulas'])
      while pending:
        deferred = []
        for formula in pending:
          try:
            samples = evaluate({'channels': request['channels'], 'formula': formula})
            request['channels'][formula['name']] = samples
            result['results'][formula['name']] = samples
          except KeyError as exc:
            deferred.append(formula)
            result['errors'][formula['name']] = f'Missing input: {exc}'
          except Exception as exc:
            result['errors'][formula['name']] = f'{type(exc).__name__}: {exc}'
        if len(deferred) == len(pending):
          break
        pending = deferred
      for name in result['results']:
        result['errors'].pop(name, None)
    else:
      result = {'samples': evaluate(request)}
  except Exception as exc:
    result = {'error': f'{type(exc).__name__}: {exc}'}
  with open(sys.argv[2], 'w') as f:
    json.dump(result, f, allow_nan=False)
