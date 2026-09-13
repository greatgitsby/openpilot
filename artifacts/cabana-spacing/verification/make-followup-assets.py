import json
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
root=Path('/tmp/cabana-followup'); out=Path('artifacts/cabana-spacing')
font=ImageFont.truetype('openpilot/selfdrive/assets/fonts/Inter-Regular.ttf',16)
rows=[
 ('playback-docked','playback-centering','Playback icons: exact visible center',(1006,296,1106,336),4),
 ('find-signal','numeric-find-signal','Find Signal: shared plus/minus component',(60,60,960,260),1),
 ('find-similar','numeric-find-similar','Find Similar Bits: shared plus/minus component',(60,60,760,185),1),
 ('settings','numeric-settings','Settings: shared plus/minus component',(500,273,900,628),1),
 ('edit-message','numeric-edit-message','Edit Message: shared plus/minus component',(400,270,1000,630),1),
 ('signal-size','numeric-signal-size','Inline signal size: shared plus/minus component',(417,520,958,576),2),
 ('demo-chart','chart-inset','Docked chart: consistent content padding',(1006,354,1392,590),1),
 ('floating-chart','floating-inset','Floating chart: consistent content padding',(279,199,1119,463),1),
]
for source,name,title,box,scale in rows:
 frames=[]
 for variant in ['before','after']:
  crop=Image.open(root/variant/(source+'.png')).convert('RGB').crop(box)
  crop.save(out/('followup-'+name+'-'+variant+'.png'))
  if scale>1: crop=crop.resize((crop.width*scale,crop.height*scale),Image.Resampling.NEAREST)
  frame=Image.new('RGB',(crop.width,crop.height+36),'#17212b');frame.paste(crop,(0,36))
  ImageDraw.Draw(frame).text((12,8),variant.title()+(' · '+str(scale)+'× native pixels' if scale>1 else ''),font=font,fill='white')
  frames.append(frame)
 frames[0].save(out/('followup-'+name+'-ab.gif'),save_all=True,append_images=frames[1:],duration=[1000,1000],loop=0,disposal=2,optimize=False)
for name in ['demo-chart','demo-floating']:
 Image.open(root/'after'/(name+'.png')).crop((0,0,1400,900)).save(out/('route-'+name+'.png'))
(out/'followup-manifest.json').write_text(json.dumps([dict(source=s,name=n,title=t,box=b,scale=z) for s,n,t,b,z in rows],indent=2)+'\n')
print('Created 8 comparisons and 2 demo-route screenshots')
