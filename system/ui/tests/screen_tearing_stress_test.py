#!/usr/bin/env python3

import pyray as rl
import random
from openpilot.common.realtime import config_realtime_process
from openpilot.system.ui.lib.application import gui_app, DEFAULT_TEXT_COLOR, DEFAULT_TEXT_SIZE
from openpilot.system.ui.widgets import Widget
from openpilot.system.ui.widgets.scroller import Scroller

class Line(Widget):
    def __init__(self, text: str, font_size: int = DEFAULT_TEXT_SIZE):
        super().__init__()
        self._text = text
        self._font = gui_app.font()
        self._font_size = font_size
        self._line_height = int(self._font_size * 1.3)
        self._left_padding = 40
        self._rect = rl.Rectangle(0, 0, 0, self._line_height)

    def _render(self, rect: rl.Rectangle):
        y = rect.y + (self._line_height - self._font_size) / 2
        rl.draw_text_ex(self._font, self._text, rl.Vector2(rect.x + self._left_padding, y), float(self._font_size), 0, DEFAULT_TEXT_COLOR)


class Shredder(Widget):
    def __init__(self):
        super().__init__()
        self._alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;-_+=*/\\|<>[]{}()"
        self._num_lines = 800  # large enough for stress without overdraw cost
        items = [Line(self._gen_line(i)) for i in range(self._num_lines)]
        self._scroller = Scroller(items, line_separator=False, pad_end=True)

    def _gen_line(self, idx: int) -> str:
        rnd = random.Random(idx)
        length = rnd.randint(60, 120)
        return "".join(rnd.choice(self._alphabet) for _ in range(length))

    def _render(self, rect: rl.Rectangle):
        self._scroller.render(rect)

def main():
    config_realtime_process([1, 2], 1)

    gui_app.init_window("Screen Tearing Stress Test")
    shredder = Shredder()
    shredder.set_rect(rl.Rectangle(0, 0, gui_app.width, gui_app.height))

    for should_render in gui_app.render():
        if should_render:
            shredder.render()

    gui_app.close()

if __name__ == "__main__":
    main()
