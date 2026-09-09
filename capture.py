import os
os.environ.update(OFFSCREEN='1', SCALE='1', BIG='0')
import sys
sys.path.insert(0, os.environ.get('OPENPILOT_ROOT', os.getcwd()))
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
import pyray as rl
from openpilot.system.ui.lib.application import gui_app
from openpilot.common.esim.base import Profile
from openpilot.common import qrcode
from types import ModuleType
state=ModuleType('openpilot.selfdrive.ui.ui_state')
state.ui_state=SimpleNamespace(params=SimpleNamespace(put_bool=lambda *args:None))
state.device=SimpleNamespace(awake=True)
sys.modules[state.__name__]=state
camera_module=ModuleType('openpilot.selfdrive.ui.mici.onroad.cameraview')
camera_module.CameraView=object
sys.modules[camera_module.__name__]=camera_module
from openpilot.selfdrive.ui.mici.layouts.settings.network import esim_ui as e
from openpilot.selfdrive.ui.mici.widgets.dialog import BigInputDialog, BigConfirmationDialog
out=Path(__file__).parent
now=[10.0]
rl.get_time=lambda:now[0]
rl.get_frame_time=lambda:1/60
class Manager:
  busy=False
  def __init__(self):
    self.profiles=[Profile('8985235000000042','',True,'Webbing'), Profile('8901260000001337','Travel',False,'Demo carrier')]
  @property
  def active_profile(self): return next((p for p in self.profiles if p.enabled),None)
  def refresh_profiles(self): pass
  def switch_profile(self,iccid):
    self.busy=True
    self.profiles=[replace(p,enabled=p.iccid==iccid) for p in self.profiles]
    self.on_profiles_updated()
  def delete_profile(self,iccid): pass
  def nickname_profile(self,*args): pass

gui_app.init_window('eSIM screenshot suite')
print('UI source:',e.__file__, 'size',gui_app.width,gui_app.height,flush=True)
rect=rl.Rectangle(0,0,gui_app.width,gui_app.height)
def draw(widget,n=1):
  for _ in range(n):
    now[0]+=1/60
    rl.begin_drawing();rl.clear_background(rl.BLACK);widget.render(rect);rl.end_drawing()
def save(name):
  im=rl.load_image_from_screen();rl.export_image(im,str(out/f'{name}.png'));rl.unload_image(im)
def animate(widget,name,frames=90):
  from PIL import Image
  images=[]
  for i in range(frames):
    draw(widget,2)
    im=rl.load_image_from_screen()
    path=out/'animation-frame.png'
    rl.export_image(im,str(path));rl.unload_image(im)
    images.append(Image.open(path).convert('RGB'))
  images[0].save(out/f'{name}.gif',save_all=True,append_images=images[1:],duration=33,loop=0)
  path.unlink()
def show(widget,name):
  widget.show_event();draw(widget,90);save(name)
manager=Manager();ui=e.EsimUI(manager,lambda:True)
show(ui,'01-profiles-prime-active')
ui._scroller.scroll_to(ui._scroller.items[-1].rect.x-20);draw(ui,60);save('02-add-profile')
manager.busy=True;draw(ui,15);save('03-operation-busy');manager.busy=False
# Scanner chrome from production widget; synthetic camera surface avoids publishing private camera footage.
class Camera:
  frame=None
  def _update_state(self): pass
  def close(self): pass
  def _render(self,r):
    rl.draw_rectangle_rec(r,rl.Color(38,40,43,255))
    if self.frame:
      rl.draw_rectangle_rounded(rl.Rectangle(175,12,186,218),.12,10,rl.Color(18,18,18,255))
      rl.draw_texture_pro(qrtex,rl.Rectangle(0,0,qrtex.width,qrtex.height),rl.Rectangle(193,32,150,150),rl.Vector2(0,0),0,rl.WHITE)
qrtex=qrcode.make_texture('LPA:1$example.invalid$DEMO-NOT-A-REAL-ACTIVATION-CODE')
e.CameraView=lambda *args:Camera()
e.ui_state=SimpleNamespace(params=SimpleNamespace(put_bool=lambda *args:None))
scanner=e.QRScannerDialog(lambda data:None)
show(scanner,'04-camera-starting')
scanner._camera_view.frame=True
scanner._last_scan_time=float('inf')
draw(scanner,30);save('05-camera-hold')
scanner._scan_thread=SimpleNamespace(is_alive=lambda:False);scanner._scan_result='https://example.invalid'
draw(scanner,1);save('06-not-lpa-code')
scanner._last_scan_time=float('inf')
animate(scanner,'qr-invalid-reset',60)
draw(scanner,66);save('07-camera-hold-reset')
show(BigInputDialog('enter a nickname...',minimum_length=0),'08-nickname-empty')
show(BigInputDialog('enter a nickname...',default_text='Travel',minimum_length=0),'09-nickname-filled')
install=e.InstallingProfileDialog();show(install,'10-installing');animate(install,'installing',72)
for i in range(3):
 draw(install,36);save(f'10-installing-dots-{i}')
# Actual profile click method triggers the existing movement and optimistic active state.
manager=Manager();ui=e.EsimUI(manager,lambda:True);ui.show_event();draw(ui,90)
ui._scroller.scroll_to(ui._scroller.items[1].rect.x-20);draw(ui,60);save('11-profile-inactive-actions')
ui._on_profile_clicked(manager.profiles[1])
animate(ui,'profile-activation',120)
# Reset the scene to collect distinct snapshots of the same animation.
manager=Manager();ui=e.EsimUI(manager,lambda:True);ui.show_event();draw(ui,90)
ui._scroller.scroll_to(ui._scroller.items[1].rect.x-20);draw(ui,60)
ui._on_profile_clicked(manager.profiles[1])
for i,n in enumerate((6,12,18,24,40)):
 draw(ui,n);save(f'12-activation-{i}')
manager.busy=False;draw(ui,60);save('13-travel-active')
show(BigInputDialog('nickname',default_text='Travel',minimum_length=0),'14-rename')
icon=gui_app.texture('icons_mici/settings/network/new/trash.png',54,64)
show(BigConfirmationDialog('slide to delete',icon,lambda:None,red=True),'15-delete-confirmation')
for name,error in [('16-no-internet','no internet connection\nconnect to wifi or\ncellular to install'),('17-download-error','AuthenticateClient failed: activation code has already been used. Please contact your eSIM provider.'),('18-download-timeout','Profile download timed out. Please try again.')]:
 captured=[]
 original=gui_app.push_widget;gui_app.push_widget=captured.append
 ui._on_error(error)
 gui_app.push_widget=original
 show(captured[0],name)
manager=Manager();manager.profiles=[];ui=e.EsimUI(manager,lambda:True);show(ui,'19-empty-profiles')
gui_app.close()
