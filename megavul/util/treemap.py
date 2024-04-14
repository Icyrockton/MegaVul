import plotly.express as px
import pandas as pd
from megavul.util.color import interpolate_in_colors

d = {'torvalds/linux': 1673, 'wireshark': 322, 'ImageMagick': 321, 'tensorflow': 287, 'ffmpeg': 286, 'chromium': 285,
     'gpac': 225, 'android': 225, 'php/php-src': 171, 'xen-project/xen': 171, 'binutils-gdb': 152, 'vim': 149,
     'openssl': 125, 'qemu': 113, 'radareorg/radare2': 105, 'the-tcpdump-group/tcpdump': 96,
     'ArtifexSoftware/ghostpdl': 73, 'freetype/freetype2': 49, 'jerryscript-project/jerryscript': 45, 'poppler': 45}

cur_max = max(d)
cur_min = min(d)


data = {
    'name': map(lambda x:x.split('/')[-1],list(d.keys())),
    'cnt': list(d.values()),
    'label_name' : [str(round(i/8203 * 100,4)) for i in d.values()]
}
print(data['cnt'])
colors = interpolate_in_colors(data['cnt'])
data['colors'] = colors
print(colors)

df = pd.DataFrame(data)
print(df)

fig = px.treemap(
    df , path=['name'], values='cnt',
color='cnt' , labels='label_name'
)
fig.update_layout(width=800,height=400)
fig.write_image('treemap.svg')
# fig.show()
