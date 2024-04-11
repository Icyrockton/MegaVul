import math

import numpy as np
from matplotlib.colors import to_rgba, to_hex


def interpolate_rgba(rgba1, rgba2, t):
    r1, g1, b1, a1 = rgba1
    r2, g2, b2, a2 = rgba2

    r = r1 + t * (r2 - r1)
    g = g1 + t * (g2 - g1)
    b = b1 + t * (b2 - b1)
    a = a1 + t * (a2 - a1)
    return r, g, b, a


def interpolate_in_colors(data: list,
                          colors: list[str] = [
                              "00732A",
"#008631",
"#00ab41",
"#00c04b",
"#1fd655",
"#39e75f",
"#5ced73",
"#83f28f",
"#abf7b1",
"#cefad0",]):
    colors = list(reversed(colors))
    sort_index = np.array(data).argsort()
    each_group_num = math.ceil(len(data ) / (len(colors)-1))
    result_colors = []
    print(len(colors))
    print(len(data))
    print(each_group_num)

    for idx, num in enumerate(data):
        sort_idx = sort_index[idx]
        group_idx = int(sort_idx / each_group_num)
        color_lower = to_rgba(colors[group_idx])
        color_upper = to_rgba(colors[group_idx + 1])
        in_group_step = ((sort_idx % each_group_num) + 1) / each_group_num
        print(group_idx)
        print(color_lower, color_upper)
        print(interpolate_rgba(color_lower, color_upper, in_group_step))
        interpolated_color = to_hex(interpolate_rgba(color_lower, color_upper, in_group_step))
        result_colors.append(interpolated_color)

    return result_colors
