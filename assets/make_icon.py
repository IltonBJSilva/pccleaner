"""Gera assets/icon.ico (16–256 px) e assets/icon.png com Pillow.

Motivo: disco (gradiente azul→ciano) + vassoura diagonal + brilhos.
Uso: python assets/make_icon.py
"""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent
SS = 4                      # supersampling
SIZE = 256 * SS


def _gradient(size: int, c1, c2) -> Image.Image:
    g = Image.new("RGBA", (64, 64))
    px = g.load()
    for y in range(64):
        for x in range(64):
            t = (x + y) / 126
            px[x, y] = tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)) + (255,)
    return g.resize((size, size), Image.BICUBIC)


def _sparkle(d: ImageDraw.ImageDraw, x: float, y: float, r: float) -> None:
    pts = [(x, y - r), (x + r * .28, y - r * .28), (x + r, y), (x + r * .28, y + r * .28),
           (x, y + r), (x - r * .28, y + r * .28), (x - r, y), (x - r * .28, y - r * .28)]
    d.polygon(pts, fill=(255, 255, 255, 240))


def draw_icon() -> Image.Image:
    s = SIZE
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    shadow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((s * .08, s * .11, s * .92, s * .95), radius=s * .22,
                                             fill=(0, 0, 0, 110))
    img.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(s * .025)))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle((s * .06, s * .06, s * .94, s * .94), radius=s * .22, fill=255)
    img.paste(_gradient(s, (37, 99, 235), (6, 182, 212)), (0, 0), mask)

    # disco em camada própria (mescla a transparência)
    layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx, cy, r = s * .42, s * .45, s * .25
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(255, 255, 255, 55), outline=(255, 255, 255, 200),
              width=int(s * .018))
    r2 = s * .065
    d.ellipse((cx - r2, cy - r2, cx + r2, cy + r2), fill=(255, 255, 255, 230))
    d.arc((cx - r * .7, cy - r * .7, cx + r * .7, cy + r * .7), 200, 290, fill=(255, 255, 255, 170),
          width=int(s * .014))
    img.alpha_composite(layer)

    d = ImageDraw.Draw(img)
    x0, y0, x1, y1 = s * .80, s * .20, s * .56, s * .62
    d.line((x0, y0, x1, y1), fill=(255, 255, 255, 255), width=int(s * .045))
    d.ellipse((x0 - s * .028, y0 - s * .028, x0 + s * .028, y0 + s * .028), fill=(255, 255, 255, 255))
    ux, uy = x1 - x0, y1 - y0
    ln = math.hypot(ux, uy)
    ux, uy = ux / ln, uy / ln
    px_, py_ = -uy, ux
    w0, w1, L = s * .07, s * .17, s * .22
    d.polygon([(x1 + px_ * w0, y1 + py_ * w0), (x1 - px_ * w0, y1 - py_ * w0),
               (x1 + ux * L - px_ * w1, y1 + uy * L - py_ * w1),
               (x1 + ux * L + px_ * w1, y1 + uy * L + py_ * w1)], fill=(253, 224, 71, 255))
    d.line((x1 + px_ * w0 * 1.1, y1 + py_ * w0 * 1.1, x1 - px_ * w0 * 1.1, y1 - py_ * w0 * 1.1),
           fill=(234, 88, 12, 255), width=int(s * .03))
    for k in range(-3, 4):
        t = k / 3.5
        d.line((x1 + ux * s * .05 + px_ * w0 * t, y1 + uy * s * .05 + py_ * w0 * t,
                x1 + ux * L * .95 + px_ * w1 * t * .95, y1 + uy * L * .95 + py_ * w1 * t * .95),
               fill=(202, 138, 4, 255), width=int(s * .008))
    for sx, sy, rr in ((.80, .70, .045), (.88, .58, .028), (.70, .84, .03)):
        _sparkle(d, s * sx, s * sy, s * rr)
    return img.resize((256, 256), Image.LANCZOS)


def main() -> None:
    icon = draw_icon()
    icon.save(HERE / "icon.png")
    sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon.save(HERE / "icon.ico", format="ICO", sizes=sizes)
    print(f"Icone gerado em {HERE / 'icon.ico'}")


if __name__ == "__main__":
    main()
