#!/usr/bin/env python3
"""Generates the Cybervulcan "Vulcan V" icon set from simple vector shapes.

Outputs (committed to the repo, re-run after changing the design):
  assets/icons/logo.svg                      master logo
  assets/icons/logo_512.png                  logo on the night background
  assets/icons/tray_{green,amber,red,purple,grey}.{svg,png,ico}
  windows/runner/resources/app_icon.ico
  installer/cybervulcan.ico
  android/app/src/main/res/mipmap-*/ic_launcher.png (legacy, pre-API 26)

The Android adaptive icon (res/drawable/ic_launcher_*.xml) and the in-app
mark (lib/src/ui/widgets/vulcan_logo.dart) are drawn separately with the
same geometry.

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
    'red': '#FF6B6F',
    'purple': '#B794F4',
    'grey': '#8A8F98',
}
INK = '#0B0E17'
V_PATH = 'M18 16 L30 16 L30 30 L50 74 L70 30 L70 16 L82 16'


def logo_svg(bg=None, size=256):
    """Full mark: ember V, cyan tunnel line and ring, glowing exit node."""
    bg_el = f'<rect width="100" height="100" rx="22" fill="{bg}"/>' if bg else ''
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 100 100">
  <defs>
    <linearGradient id="lava" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#FFD08A"/>
      <stop offset="0.5" stop-color="#FF7A3D"/>
      <stop offset="1" stop-color="#C2410C"/>
    </linearGradient>
    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="2"/>
    </filter>
  </defs>
  {bg_el}
  <path d="{V_PATH}" fill="none" stroke="#FF7A3D" stroke-opacity="0.45" stroke-width="9"
        stroke-linejoin="round" stroke-linecap="round" filter="url(#glow)"/>
  <path d="{V_PATH}" fill="none" stroke="url(#lava)" stroke-width="7"
        stroke-linejoin="round" stroke-linecap="round"/>
  <path d="M50 16 V62" stroke="#5CE1E6" stroke-width="3" stroke-linecap="round"/>
  <circle cx="50" cy="16" r="4" fill="none" stroke="#5CE1E6" stroke-width="2"/>
  <circle cx="50" cy="84" r="9" fill="#FF7A3D" opacity="0.4" filter="url(#glow)"/>
  <circle cx="50" cy="84" r="5" fill="#FFD08A"/>
  <circle cx="18" cy="16" r="3" fill="#FFD08A"/>
  <circle cx="82" cy="16" r="3" fill="#FFD08A"/>
</svg>
'''


def tray_svg(color):
    """Simplified mark for 16-32 px: dark disc, status-coloured V and node."""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <circle cx="128" cy="128" r="124" fill="{INK}"/>
  <path d="M44 58 H84 V94 L128 190 L172 94 V58 H212" fill="none" stroke="{color}" stroke-width="30"
        stroke-linejoin="round" stroke-linecap="round"/>
  <circle cx="128" cy="226" r="17" fill="{color}"/>
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
    render(logo_svg(bg=INK), 512).save(os.path.join(ICONS, 'logo_512.png'))

    for name, color in STATUS.items():
        svg = tray_svg(color)
        write(os.path.join(ICONS, f'tray_{name}.svg'), svg)
        render(svg, 64).save(os.path.join(ICONS, f'tray_{name}.png'))
        save_ico(svg, os.path.join(ICONS, f'tray_{name}.ico'), sizes=(16, 20, 24, 32, 40, 48, 64))

    app_svg = logo_svg(bg=INK)
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
