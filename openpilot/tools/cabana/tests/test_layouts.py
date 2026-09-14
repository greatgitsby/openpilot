import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from openpilot.tools.cabana.analysis.cabana_equations import compile_numeric_equation
from openpilot.tools.cabana.analysis.convert_layouts import convert

CABANA = Path(__file__).resolve().parents[1]
XML = CABANA.parent / 'plotjuggler/layouts'


class TestLayouts(unittest.TestCase):
  def test_audited_corpus(self):
    totals = [0, 0, 0, 0, 0, 0, 0]
    translations = json.loads((CABANA / 'analysis/layout_equations.json').read_text())
    for path in sorted(XML.glob('*.xml')):
      with self.subTest(layout=path.stem):
        doc = json.loads((CABANA / 'layouts' / (path.stem + '.json')).read_text())
        self.assertEqual(doc, convert(path, translations[path.stem]))
        root = ET.parse(path).getroot()
        totals[0] += 1
        totals[1] += len(doc['pages'])
        totals[4] += len(doc['equations'])
        for page, tab in zip(doc['pages'], root.findall('./tabbed_widget/Tab'), strict=True):
          self.assertEqual(page['name'], tab.attrib['tab_name'])
          for pane, plot in zip(page['panes'], tab.findall('.//plot'), strict=True):
            totals[2] += 1
            for curve, original in zip(pane['curves'], plot.findall('curve'), strict=True):
              totals[3] += 1
              color = '#' + ''.join(f'{channel:02x}' for channel in curve['color'][:3])
              self.assertEqual(color.lower(), original.attrib['color'].lower())
              transform = original.find('transform')
              if transform is not None:
                self.assertEqual(curve['alias'], transform.get('alias', ''))
                if transform.get('name') == 'Derivative':
                  totals[5] += 1
                  if curve['transform']['divisor'] == 1:
                    totals[6] += 1
                elif transform.get('name') == 'Scale/Offset':
                  for native, xml in [('scale', 'value_scale'), ('offset', 'value_offset'), ('time_offset', 'time_offset')]:
                    self.assertEqual(curve['transform'][native], float(transform.find('options').get(xml)))
          self.assertEqual(len(self.rectangles(page['dock']['children'][1])), len(page['panes']))
        for equation in doc['equations']:
          self.assertEqual(equation['language'], 'python')
          compile_numeric_equation(equation['globals'], equation['function'], len(equation['additional']))
    self.assertEqual(totals, [14, 23, 89, 212, 17, 25, 21])

  @staticmethod
  def rectangles(tree, x=0, y=0, w=1, h=1):
    if 'children' not in tree:
      return [(x, y, w, h)]
    ratio = tree['ratio']
    a, b = tree['children']
    if tree['axis'] == 'x':
      return TestLayouts.rectangles(a, x, y, w * ratio, h) + TestLayouts.rectangles(b, x + w * ratio, y, w * (1-ratio), h)
    return TestLayouts.rectangles(a, x, y, w, h * ratio) + TestLayouts.rectangles(b, x, y + h * ratio, w, h * (1-ratio))

  def test_nested_three_way_split(self):
    doc = json.loads((CABANA / 'layouts/can-states.json').read_text())
    rectangles = self.rectangles(doc['pages'][0]['dock']['children'][1])
    self.assertEqual(len(rectangles), 5)
    for i, (x, y, w, h) in enumerate(rectangles[2:]):
      self.assertAlmostEqual(x, i / 3)
      self.assertAlmostEqual(w, 1 / 3)
      self.assertAlmostEqual(y, 0.500381)
      self.assertAlmostEqual(h, 0.499619)

  def test_untranslated_lua_is_rejected(self):
    with self.assertRaisesRegex(ValueError, 'Unsupported Lua'):
      convert(XML / 'tuning.xml', [])

  def test_five_second_engagement_gate(self):
    doc = json.loads((CABANA / 'layouts/tuning.json').read_text())
    equation = next(e for e in doc['equations'] if e['name'] == 'engaged curvature vehicle model')
    calc = compile_numeric_equation(equation['globals'], equation['function'], 2)
    for time, pressed, enabled, expected in [(100, 1, 1, 0), (105, 0, 1, 0), (105.01, 0, 1, 2),
                                              (106, 0, 0, 0), (111, 0, 1, 0), (111.01, 0, 1, 2)]:
      self.assertEqual(calc(float(time), 2.0, float(pressed), float(enabled)), expected)


if __name__ == '__main__':
  unittest.main()
