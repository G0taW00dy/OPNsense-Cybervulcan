#!/usr/bin/env python3
"""Generates the OPn icon set from simple vector shapes.

Outputs (committed to the repo, re-run after changing the design):
  assets/icons/logo.svg                      master logo (ring + P + n)
  assets/icons/tray_{green,amber,red,purple,grey}.{svg,png,ico}
  windows/runner/resources/app_icon.ico
  android/app/src/main/res/mipmap-*/ic_launcher.png (legacy, pre-API 26)

Requires: rsvg-convert (librsvg) and Pillow.
Usage: python3 tool/make_icons.py
"""
import io
import os
import subprocess
import sys

from PIL import Image

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ICONS = os.path.join(ROOT, 'assets', 'icons')

STATUS = {
    'green': '#2ECC71',
    'amber': '#F5A623',
    'red': '#E5484D',
    'purple': '#9B5DE5',
    'grey': '#8A8F98',
}
INK = '#0E1320'


def logo_svg(accent='#5CE1E6', with_n=True, bg=None, size=256):
    """Full mark: liquid-glass O ring, P stem through it, lower-case n."""
    w = 372 if with_n else 256
    bg_el = f'<rect width="{w}" height="256" rx="56" fill="{bg}"/>' if bg else ''
    n_el = (
        '<path d="M268 216 V152 a36 36 0 0 1 72 0 V216" fill="none" stroke="url(#ink)" '
        'stroke-width="24" stroke-linecap="round" stroke-linejoin="round"/>'
        if with_n else ''
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{size * w // 256}" height="{size}" viewBox="0 0 {w} 256">
  <defs>
    <linearGradient id="glass" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#FFFFFF"/>
      <stop offset="0.3" stop-color="{accent}"/>
      <stop offset="1" stop-color="#3A7BD5"/>
    </linearGradient>
    <linearGradient id="ink" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#FFFFFF"/>
      <stop offset="1" stop-color="#C9D6EA"/>
    </linearGradient>
    <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="8"/>
    </filter>
  </defs>
  {bg_el}
  <circle cx="128" cy="128" r="84" fill="none" stroke="{accent}" stroke-opacity="0.45" stroke-width="34" filter="url(#glow)"/>
  <circle cx="128" cy="128" r="84" fill="{INK}" fill-opacity="0.55" stroke="url(#glass)" stroke-width="30"/>
  <path d="M66 96 A66 66 0 0 1 112 56" fill="none" stroke="#FFFFFF" stroke-opacity="0.85" stroke-width="9" stroke-linecap="round"/>
  <path d="M108 248 V82 H140 A30 30 0 0 1 140 142 H108" fill="none" stroke="url(#ink)" stroke-width="26" stroke-linecap="round" stroke-linejoin="round"/>
  {n_el}
</svg>
'''


def tray_svg(color):
    """Simplified mark for 16-32 px: status-coloured ring, dark core, white P."""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <circle cx="128" cy="128" r="100" fill="{INK}" stroke="{color}" stroke-width="44"/>
  <path d="M104 196 V70 H138 A33 33 0 0 1 138 136 H104" fill="none" stroke="#FFFFFF" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
'''


def render(svg_text, px):
    out = subprocess.run(
        ['rsvg-convert', '-w', str(px), '-h', str(px), '--keep-aspect-ratio'],
        input=svg_text.encode(), capture_output=True, check=True,
    ).stdout
    img = Image.open(io.BytesIO(out)).convert('RGBA')
    if img.size != (px, px):  # pad non-square renders onto a square canvas
        canvas = Image.new('RGBA', (px, px), (0, 0, 0, 0))
        canvas.paste(img, ((px - img.width) // 2, (px - img.height) // 2))
        img = canvas
    return img


def save_ico(svg_text, path, sizes=(16, 20, 24, 32, 40, 48, 64, 128, 256)):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    big = render(svg_text, 256)
    big.save(path, format='ICO', sizes=[(s, s) for s in sizes])


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(text)


def main():
    os.makedirs(ICONS, exist_ok=True)
    write(os.path.join(ICONS, 'logo.svg'), logo_svg())
    render(logo_svg(with_n=False, bg=INK), 512).save(os.path.join(ICONS, 'logo_512.png'))

    for name, color in STATUS.items():
        svg = tray_svg(color)
        write(os.path.join(ICONS, f'tray_{name}.svg'), svg)
        render(svg, 64).save(os.path.join(ICONS, f'tray_{name}.png'))
        save_ico(svg, os.path.join(ICONS, f'tray_{name}.ico'), sizes=(16, 20, 24, 32, 40, 48, 64))

    app_svg = logo_svg(with_n=False, bg=INK)
    save_ico(app_svg, os.path.join(ROOT, 'windows', 'runner', 'resources', 'app_icon.ico'))
    save_ico(app_svg, os.path.join(ROOT, 'installer', 'cybervulcan.ico'))

    res = os.path.join(ROOT, 'android', 'app', 'src', 'main', 'res')
    for folder, px in {'mdpi': 48, 'hdpi': 72, 'xhdpi': 96, 'xxhdpi': 144, 'xxxhdpi': 192}.items():
        d = os.path.join(res, f'mipmap-{folder}')
        os.makedirs(d, exist_ok=True)
        render(app_svg, px).save(os.path.join(d, 'ic_launcher.png'))
    print('icons written', file=sys.stderr)


if __name__ == '__main__':
    main()
