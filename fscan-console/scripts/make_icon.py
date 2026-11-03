from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

S = 1024
OUT = Path(__file__).resolve().parent.parent / "assets"
OUT.mkdir(parents=True, exist_ok=True)


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle((8, 8, size - 8, size - 8), radius=radius, fill=255)
    return mask


def main() -> None:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((8, 8, S - 8, S - 8), radius=225, fill=(8, 13, 19, 255))

    # 背景微光
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse((120, 40, S - 120, S - 40), fill=(90, 216, 230, 26))
    glow = glow.filter(ImageFilter.GaussianBlur(90))
    img.alpha_composite(glow)

    cx = cy = S / 2

    # 扫描扇区
    wedge = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    wd = ImageDraw.Draw(wedge)
    for i in range(70):
        a0 = -60 + i * 0.9
        alpha = int(70 * (1 - i / 70) ** 2)
        wd.pieslice(
            (150, 150, S - 150, S - 150),
            start=a0,
            end=a0 + 1.2,
            fill=(90, 216, 230, alpha),
        )
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).ellipse((140, 140, S - 140, S - 140), fill=255)
    wedge.putalpha(Image.composite(wedge.getchannel("A"), Image.new("L", (S, S), 0), mask))
    img.alpha_composite(wedge)

    ring_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring_layer)
    for radius, alpha, width in ((410, 235, 10), (300, 90, 7), (190, 90, 7), (96, 120, 6)):
        rd.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), outline=(247, 184, 75, alpha), width=width)
    rd.line((cx - 470, cy, cx + 470, cy), fill=(247, 184, 75, 46), width=4)
    rd.line((cx, cy - 470, cx, cy + 470), fill=(247, 184, 75, 46), width=4)
    img.alpha_composite(ring_layer)

    # 外圈刻度
    tick_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    td = ImageDraw.Draw(tick_layer)
    for i in range(48):
        ang = math.radians(i * 7.5)
        r1 = 455 if i % 6 else 440
        r2 = 480
        x1, y1 = cx + math.cos(ang) * r1, cy + math.sin(ang) * r1
        x2, y2 = cx + math.cos(ang) * r2, cy + math.sin(ang) * r2
        td.line((x1, y1, x2, y2), fill=(247, 184, 75, 120 if i % 6 else 200), width=5 if i % 6 else 7)
    img.alpha_composite(tick_layer)

    # 中心光点
    core = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core)
    cd.ellipse((cx - 130, cy - 130, cx + 130, cy + 130), fill=(247, 184, 75, 50))
    core = core.filter(ImageFilter.GaussianBlur(55))
    img.alpha_composite(core)

    dot = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    dd = ImageDraw.Draw(dot)
    dd.ellipse((cx - 34, cy - 34, cx + 34, cy + 34), fill=(255, 210, 122, 255))
    img.alpha_composite(dot)

    # 侧边信号点
    for ang, radius, color in ((32, 300, (255, 107, 107, 255)), (168, 240, (90, 216, 230, 255))):
        a = math.radians(ang)
        x, y = cx + math.cos(a) * radius, cy + math.sin(a) * radius
        b = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        bd = ImageDraw.Draw(b)
        bd.ellipse((x - 26, y - 26, x + 26, y + 26), fill=(color[0], color[1], color[2], 60))
        b = b.filter(ImageFilter.GaussianBlur(18))
        img.alpha_composite(b)
        ImageDraw.Draw(img).ellipse((x - 14, y - 14, x + 14, y + 14), fill=color)

    # 圆角裁切
    img.putalpha(Image.composite(img.getchannel("A"), Image.new("L", (S, S), 0), rounded_mask(S, 225)))

    final = img.resize((512, 512), Image.LANCZOS)
    final.save(OUT / "app.png")
    final.save(OUT / "app.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
    print("saved", OUT / "app.png", OUT / "app.ico")


if __name__ == "__main__":
    main()
