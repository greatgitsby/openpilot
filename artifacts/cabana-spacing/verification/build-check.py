import subprocess
from pathlib import Path
import imgui,bootstrap_icons
r=Path(__file__).resolve().parents[3]
here=Path(__file__).resolve().parent
import os
os.chdir(r)
subprocess.run(['g++','-std=c++17','-O1','-ffunction-sections','-fdata-sections','-Iopenpilot','-I.',f'-I{imgui.INCLUDE_DIR}', '-I'+str(Path(imgui.INCLUDE_DIR).parent/'include'), '-DCABANA_FONTS_DIR="'+str(r/'openpilot/selfdrive/assets/fonts')+'"','-DBOOTSTRAP_ICONS_TTF="'+str(bootstrap_icons.TTF_PATH)+'"',str(here/'check-spacing.cc'),'openpilot/tools/cabana/ui/util.cc','openpilot/tools/cabana/ui/theme.cc',str(Path(imgui.LIB_DIR)/'libimgui.a'),str(Path(imgui.LIB_DIR)/'libglfw3.a'),'-Wl,--gc-sections','-lGL','-ldl','-lpthread','-o','/tmp/cabana-spacing-geometry'],check=True)
