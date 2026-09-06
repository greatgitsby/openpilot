#!/usr/bin/env python3
"""Read PlotJuggler XML as a data format; no PlotJuggler runtime is required."""

import ast
import re
import textwrap
import json
import sys
import xml.etree.ElementTree as ET


def translate_lua(code):
  """The arithmetic/conditional subset used by the bundled layouts; reject other syntax."""
  output = []
  indent = 0
  pending = ''
  for original in code.splitlines():
    line = original.split('--', 1)[0].strip()
    if not line:
      continue
    line = pending + line
    if line.endswith(('+', '-', '*', '/')):
      pending = line + ' '
      continue
    pending = ''
    line = line.replace('^', '**').replace('~=', '!=').replace('math.abs(', 'abs(')
    line = line.replace('math.atan(', 'math.atan2(')
    line = re.sub(r'\blocal\s+', '', line)
    for old, new in [('true', 'True'), ('false', 'False'), ('nil', 'None')]:
      line = re.sub(r'\b' + old + r'\b', new, line)
    if line == 'end':
      indent -= 1
      if indent < 0:
        raise ValueError('Unbalanced Lua block')
      continue
    if line == 'else' or line.startswith('elseif '):
      indent -= 1
      line = line.replace('elseif ', 'elif ', 1)
    block = line == 'else' or line.endswith(' then')
    if block:
      line = line.removesuffix(' then') + ':'
    output.append('  ' * indent + line)
    if block:
      indent += 1
  if indent or pending:
    raise ValueError('Incomplete Lua formula')
  return '\n'.join(output)


def import_xml(path):
  root = ET.parse(path).getroot()

  def pane(element):
    if element.tag == 'DockSplitter':
      children = [pane(child) for child in element if child.tag in ('DockArea', 'DockSplitter')]
      return {
        'split': 'vertical' if element.get('orientation') == '-' else 'horizontal',
        'children': children,
        'sizes': [float(n) for n in element.get('sizes', '').split(';') if n],
      }
    plot = element.find('plot')
    if plot is None:
      return {'kind': 'plot', 'title': element.get('name', 'Plot'), 'curves': []}
    curves = []
    for entry in plot.findall('curve'):
      curve = dict(entry.attrib)
      transform = entry.find('transform')
      if transform is not None:
        curve['label'] = transform.get('alias', '')
        options = transform.find('options')
        if transform.get('name') in ('1st Derivative', 'Derivative'):
          curve['derivative'] = True
          if options is not None and options.get('radioChecked') == 'radioCustom':
            curve['derivative_dt'] = float(options.get('lineEdit', '0'))
        elif transform.get('name') == 'Scale/Offset' and options is not None:
          curve['value_scale'] = float(options.get('value_scale', '1'))
          curve['value_offset'] = float(options.get('value_offset', '0'))
        else:
          raise ValueError(f'Unsupported XML transform: {transform.get("name")}')
      curves.append(curve)
    limits = plot.find('limitY')
    saved_range = plot.find('range')
    return {
      'kind': 'plot',
      'title': element.get('name', 'Plot'),
      'curves': curves,
      'limitY': {k: float(v) for k, v in limits.attrib.items()} if limits is not None else {},
      'style': 2 if plot.get('style') == 'Dots' else 0,
      'range': {k: float(v) for k, v in saved_range.attrib.items()} if saved_range is not None else {},
    }

  tabs = []
  for tab in root.findall('.//tabbed_widget/Tab'):
    nodes = [pane(child) for container in tab.findall('Container') for child in container if child.tag in ('DockArea', 'DockSplitter')]
    if nodes:
      tabs.append({'name': tab.get('tab_name', 'Analysis'), 'root': nodes[0] if len(nodes) == 1 else {'split': 'horizontal', 'children': nodes}})
  if not tabs:
    raise ValueError('No PlotJuggler tabs found')
  formulas = []
  for snippet in root.findall('./customMathEquations/snippet'):
    additional = [entry.text or '' for entry in snippet.findall('./additional_sources/*')]
    globals_code = translate_lua(snippet.findtext('global', ''))
    global_names = sorted({node.id for node in ast.walk(ast.parse(globals_code)) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)})
    arguments = ['time', 'value'] + [f'v{i + 1}' for i in range(len(additional))]
    body = translate_lua(snippet.findtext('function', ''))
    if global_names:
      body = 'global ' + ', '.join(global_names) + '\n' + body
    code = 'def sample(' + ', '.join(arguments) + '):\n' + textwrap.indent(body, '  ')
    code += '\nreturn np.asarray([sample(*row) for row in zip(' + ', '.join(arguments) + ')])'
    formulas.append(
      {
        'name': snippet.get('name'),
        'linked_source': snippet.findtext('linked_source', ''),
        'additional_sources': additional,
        'globals_code': globals_code,
        'function_code': code,
      }
    )
  return {'version': 1, 'tabs': tabs, 'current_tab_index': 0, 'formulas': formulas}


if __name__ == '__main__':
  try:
    with open(sys.argv[1]) as f:
      request = json.load(f)
    result = import_xml(request['path'])
  except Exception as exc:
    result = {'error': str(exc)}
  with open(sys.argv[2], 'w') as f:
    json.dump(result, f)
