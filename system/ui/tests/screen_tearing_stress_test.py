#!/usr/bin/env python3

import pyray as rl
from openpilot.common.realtime import config_realtime_process
from openpilot.system.ui.lib.application import gui_app
from openpilot.selfdrive.ui.layouts.settings.settings import SettingsLayout

def main():
    config_realtime_process([1, 2], 1)

    gui_app.init_window("Screen Tearing Stress Test")
    shredder = SettingsLayout()
    shredder.set_rect(rl.Rectangle(0, 0, gui_app.width, gui_app.height))

    for should_render in gui_app.render():
        if should_render:
            shredder.render()

    gui_app.close()

if __name__ == "__main__":
    main()
