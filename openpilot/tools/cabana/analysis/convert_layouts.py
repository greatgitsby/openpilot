"""Build bundled native workspaces from audited XML and explicit Python translations.

This build-time converter does not translate or execute Lua. Every snippet must have
an explicitly supplied Python definition from the audited Cabana donor.
"""
import json
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET


def convert(xml_path, translations):
  root = ET.parse(xml_path).getroot()
  prefix = Path(xml_path).stem
  def identity(kind, value):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'cabana/{prefix}/{kind}/{value}'))
  by_name = {item['name']: item for item in translations}
  snippets = root.findall('.//snippet')
  missing = {item.attrib['name'] for item in snippets} - by_name.keys()
  if missing:
    raise ValueError(f'Unsupported Lua equations require explicit Python translations: {sorted(missing)}')
  refs = {name: 'equation/' + identity('equation', name) for name in by_name}
  equations = []
  for name, item in by_name.items():
    if item.get('language') != 'python':
      raise ValueError(f'Only Python equations are supported: {name}')
    equations.append(dict(item, id=identity('equation', name), source=refs.get(item['source'], item['source']),
                          additional=[refs.get(path, path) for path in item.get('additional', [])]))
  pages = []
  for page_index, tab in enumerate(root.findall('./tabbed_widget/Tab')):
    panes = []
    def node(element, page_index=page_index, panes=panes):
      if element.tag == 'DockArea':
        plots = element.findall('plot')
        if len(plots) != 1:
          raise ValueError('Expected one plot per DockArea')
        plot = plots[0]
        if plot.get('mode', 'TimeSeries') != 'TimeSeries' or plot.get('style', 'Lines') != 'Lines':
          raise ValueError('Unsupported plot mode or style')
        pane_id = identity('pane', f'{page_index}/{len(panes)}')
        curves = []
        for curve in plot.findall('curve'):
          source = curve.attrib['name']
          color = curve.get('color', '#0072b2').lstrip('#')
          transform = {'type': 0, 'scale': 1, 'offset': 0, 'time_offset': 0, 'divisor': 0, 'window': 10}
          alias = ''
          for item in curve.findall('transform'):
            options = item.find('options')
            alias = item.get('alias', '')
            if item.get('name') == 'Derivative':
              transform['type'] = 1
              if options.get('radioChecked') != 'radioActual':
                transform['divisor'] = float(options.get('lineEdit', '1'))
            elif item.get('name') == 'Scale/Offset':
              transform.update(scale=float(options.get('value_scale', '1')), offset=float(options.get('value_offset', '0')),
                               time_offset=float(options.get('time_offset', '0')))
            else:
              raise ValueError(f'Unsupported transform: {item.get("name")}')
          curves.append({'source': {'kind': 'series', 'path': refs.get(source, source)}, 'alias': alias,
                         'color': [int(color[i:i+2], 16) for i in (0, 2, 4)] + [255], 'visible': True, 'transform': transform})
        bounds = plot.find('limitY')
        saved_range = plot.find('range')
        panes.append({'id': pane_id, 'title': '' if element.get('name') == '...' else element.get('name', ''),
                      'style': 0, 'curves': curves,
                      'range': {key: float(value) for key, value in saved_range.attrib.items()} if saved_range is not None else {},
                      'y_lower': float(bounds.get('min')) if bounds is not None and bounds.get('min') else None,
                      'y_upper': float(bounds.get('max')) if bounds is not None and bounds.get('max') else None})
        return {'panes': ['###Chart/' + pane_id], 'selected': '###Chart/' + pane_id}
      children = [node(child) for child in element]
      if len(children) == 1:
        return children[0]
      sizes = [float(value) for value in element.get('sizes', '').split(';') if value]
      if len(sizes) != len(children) or any(value <= 0 for value in sizes):
        raise ValueError('Invalid split proportions')
      tree = children[-1]
      for i in range(len(children) - 2, -1, -1):
        tree = {'axis': 'x' if element.get('orientation') == '|' else 'y',
                'ratio': sizes[i] / sum(sizes[i:]), 'children': [children[i], tree]}
      return tree
    containers = tab.findall('Container')
    if len(containers) != 1:
      raise ValueError('Unsupported floating container')
    plot_tree = node(containers[0])
    pages.append({'id': identity('page', page_index), 'name': tab.get('tab_name', ''), 'panes': panes,
                  'dock': {'axis': 'x', 'ratio': 0.22, 'children': [
                    {'panes': ['###MessagesPanel', '###CenterWidget', '###VideoPanel', '###ChartsWindow'], 'selected': '###ChartsWindow'}, plot_tree]}})
  selected = root.find('./tabbed_widget/currentTabIndex')
  return {'cabana_workspace': 1, 'pages': pages, 'equations': equations,
          'active_page': int(selected.get('index', '0')) if selected is not None else 0,
          'relative_time': root.find('use_relative_time_offset').get('enabled') == '1'}


if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('xml', type=Path)
  parser.add_argument('translations', type=Path)
  parser.add_argument('output', type=Path)
  args = parser.parse_args()
  args.output.write_text(json.dumps(convert(args.xml, json.loads(args.translations.read_text())['equations']), indent=2) + '\n')
