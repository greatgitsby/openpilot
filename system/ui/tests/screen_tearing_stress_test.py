#!/usr/bin/env python3

import pyray as rl
from openpilot.common.realtime import config_realtime_process
from openpilot.system.ui.lib.application import gui_app
from openpilot.selfdrive.ui.layouts.settings.firehose import FirehoseLayout
from openpilot.selfdrive.ui.layouts.settings.settings import SettingsLayout
from openpilot.system.ui.lib.wifi_manager import WifiManager

def main():
    config_realtime_process([1, 2], 1)

    wifi = WifiManager()
    wifi.set_active(True)
    wifi.add_callbacks(networks_updated=lambda networks: print(networks))

    gui_app.init_window("Screen Tearing Stress Test")
    #shredder = FirehoseLayout()
    shredder = SettingsLayout()
    rect = rl.Rectangle(0, 0, gui_app.width, gui_app.height)
    # inset = rl.Rectangle(rect.x + 50, rect.y + 50, rect.width - 100, rect.height - 100)
    panel_rect = rl.Rectangle(rect.x + 500, rect.y, rect.width - 500, rect.height)
    shredder.set_rect(panel_rect)

    for should_render in gui_app.render():
        if should_render:
            # rl.draw_rectangle_rounded(
            #     inset, 0.04, 30, rl.Color(24, 24, 24, 255)
            # )
            shredder.render()

    gui_app.close()

if __name__ == "__main__":
    main()
