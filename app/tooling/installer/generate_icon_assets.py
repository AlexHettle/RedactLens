"""Generate raster and Windows icon assets for the RedactLens brand mark."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

CANVAS_SIZE = 1024
WIZARD_IMAGE_SIZE = (534, 1022)
SPLASH_LOGICAL_SIZE = (600, 360)
SPLASH_SCALE = 2
SPLASH_IMAGE_SIZE = tuple(dimension * SPLASH_SCALE for dimension in SPLASH_LOGICAL_SIZE)
BRAND_GREEN = (53, 111, 78, 255)
LIGHT_BG = (244, 247, 250, 255)
INK = (30, 37, 46, 255)
MUTED = (98, 107, 118, 255)
ACCENT_SOFT = (229, 242, 246, 255)
LINE = (222, 227, 231, 255)
SUCCESS = (49, 132, 84, 255)
SUCCESS_INK = (35, 107, 66, 255)
SUCCESS_SOFT = (224, 245, 230, 255)
SUCCESS_BORDER = (168, 213, 181, 255)
DARK_BG = (16, 20, 25, 255)
DARK_INK = (232, 235, 239, 255)
DARK_MUTED = (147, 153, 160, 255)
DARK_ACCENT_SOFT = (20, 40, 50, 255)
DARK_SUCCESS = (73, 164, 110, 255)
DARK_SUCCESS_INK = (108, 198, 142, 255)
DARK_SUCCESS_SOFT = (23, 53, 35, 255)
DARK_SUCCESS_BORDER = (43, 98, 66, 255)
DARK_LINE = (45, 50, 58, 255)


def _cubic(
    start: tuple[float, float],
    control_a: tuple[float, float],
    control_b: tuple[float, float],
    end: tuple[float, float],
    steps: int = 32,
) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for index in range(1, steps + 1):
        amount = index / steps
        inverse = 1 - amount
        x = (
            inverse**3 * start[0]
            + 3 * inverse**2 * amount * control_a[0]
            + 3 * inverse * amount**2 * control_b[0]
            + amount**3 * end[0]
        )
        y = (
            inverse**3 * start[1]
            + 3 * inverse**2 * amount * control_a[1]
            + 3 * inverse * amount**2 * control_b[1]
            + amount**3 * end[1]
        )
        points.append((x, y))
    return points


def render_icon() -> Image.Image:
    """Render the flat shield, inspection lens, and redaction bar mark."""
    image = Image.new("RGBA", (CANVAS_SIZE, CANVAS_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    top = (512.0, 48.0)
    left_shoulder = (128.0, 208.0)
    left_lower = (128.0, 486.0)
    bottom = (512.0, 976.0)
    right_lower = (896.0, 486.0)
    right_shoulder = (896.0, 208.0)
    shield = [top]
    shield += _cubic(top, (396, 138), (276, 190), left_shoulder)
    shield.append(left_lower)
    shield += _cubic(left_lower, (128, 714), (310, 902), bottom)
    shield += _cubic(bottom, (714, 902), (896, 714), right_lower)
    shield.append(right_shoulder)
    shield += _cubic(right_shoulder, (748, 190), (628, 138), top)
    draw.polygon(shield, fill=BRAND_GREEN)

    line_width = 88
    handle_start = (610, 596)
    handle_end = (762, 748)
    draw.line((handle_start, handle_end), fill=LIGHT_BG, width=line_width)
    radius = line_width // 2
    for center in (handle_start, handle_end):
        draw.ellipse(
            (
                center[0] - radius,
                center[1] - radius,
                center[0] + radius,
                center[1] + radius,
            ),
            fill=LIGHT_BG,
        )

    draw.ellipse((242, 218, 706, 682), outline=LIGHT_BG, width=line_width)
    draw.rounded_rectangle((336, 416, 612, 496), radius=40, fill=INK)
    return image


def render_wizard_image(icon: Image.Image) -> Image.Image:
    """Place the brand mark on a portrait canvas for welcome and finish pages."""
    width, height = WIZARD_IMAGE_SIZE
    image = Image.new("RGBA", WIZARD_IMAGE_SIZE, LIGHT_BG)
    draw = ImageDraw.Draw(image)

    # A restrained accent keeps the image recognizably RedactLens without
    # competing with the wizard's welcome text.
    draw.rectangle((0, 0, 18, height), fill=BRAND_GREEN)
    mark_size = 410
    mark = icon.resize((mark_size, mark_size), Image.Resampling.LANCZOS)
    image.alpha_composite(mark, ((width - mark_size) // 2 + 9, 255))
    return image


def _font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    windows = Path(os.environ.get("WINDIR", "C:\\Windows")) / "Fonts"
    candidates = [
        windows / ("seguisb.ttf" if bold else "segoeui.ttf"),
        Path("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(str(candidate), size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_splash_image(icon: Image.Image, *, dark: bool = False) -> Image.Image:
    """Render a high-DPI startup card at the app's 600x360 logical size."""
    scale = SPLASH_SCALE
    width, height = SPLASH_IMAGE_SIZE

    def scaled(values: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(value * scale for value in values)

    background = DARK_BG if dark else LIGHT_BG
    ink = DARK_INK if dark else INK
    muted = DARK_MUTED if dark else MUTED
    brand = BRAND_GREEN
    link = DARK_SUCCESS_INK if dark else SUCCESS_INK
    accent_soft = DARK_ACCENT_SOFT if dark else ACCENT_SOFT
    success = DARK_SUCCESS if dark else SUCCESS
    success_ink = DARK_SUCCESS_INK if dark else SUCCESS_INK
    success_soft = DARK_SUCCESS_SOFT if dark else SUCCESS_SOFT
    success_border = DARK_SUCCESS_BORDER if dark else SUCCESS_BORDER
    divider = DARK_LINE if dark else LINE
    halo_colors = (
        (
            (235, (21, 34, 42, 255)),
            (185, (20, 39, 49, 255)),
            (135, DARK_ACCENT_SOFT),
        )
        if dark
        else (
            (235, (238, 246, 249, 255)),
            (185, (232, 243, 247, 255)),
            (135, ACCENT_SOFT),
        )
    )
    image = Image.new("RGBA", SPLASH_IMAGE_SIZE, background)
    draw = ImageDraw.Draw(image)

    # Quiet depth and geometry echo the app's warm surfaces without relying
    # on transparency, which keeps PyInstaller's Windows splash edges clean.
    for radius, color in halo_colors:
        radius *= scale
        draw.ellipse((width - radius, -radius // 2, width + radius, radius * 3 // 2), fill=color)
    mark_size = 126 * scale
    mark = icon.resize((mark_size, mark_size), Image.Resampling.LANCZOS)
    image.alpha_composite(mark, scaled((47, 70)))

    draw.text(scaled((202, 76)), "RedactLens", font=_font(38 * scale, bold=True), fill=ink)
    draw.text(
        scaled((204, 129)),
        "Finds sensitive data before you share it.",
        font=_font(16 * scale),
        fill=muted,
    )

    pill = scaled((203, 174, 362, 210))
    draw.rounded_rectangle(
        pill,
        radius=18 * scale,
        fill=success_soft,
        outline=success_border,
        width=scale,
    )
    draw.ellipse(scaled((219, 187, 227, 195)), fill=success)
    draw.text(
        scaled((237, 183)),
        "On-device privacy",
        font=_font(13 * scale, bold=True),
        fill=success_ink,
    )

    draw.line(scaled((39, 273, 561, 273)), fill=divider, width=scale)
    draw.rectangle(scaled((0, 288, 600, 378)), fill=accent_soft)
    draw.rectangle(scaled((0, 0, 8, 360)), fill=brand)
    draw.ellipse(scaled((45, 314, 59, 328)), outline=link, width=3 * scale)
    draw.arc(
        scaled((49, 318, 55, 324)),
        start=300,
        end=90,
        fill=accent_soft,
        width=3 * scale,
    )
    draw.text(
        scaled((456, 315)),
        "LOCAL  •  PRIVATE",
        font=_font(10 * scale, bold=True),
        fill=muted,
    )
    return image


def generate_assets(output_directory: Path) -> tuple[Path, ...]:
    output_directory.mkdir(parents=True, exist_ok=True)
    icon = render_icon()
    png_path = output_directory / "redactlens-icon.png"
    ico_path = output_directory / "redactlens.ico"
    wizard_path = output_directory / "redactlens-installer-wizard.png"
    splash_path = output_directory / "redactlens-splash.png"
    splash_bitmap_path = output_directory / "redactlens-splash.bmp"
    dark_splash_path = output_directory / "redactlens-splash-dark.png"
    dark_splash_bitmap_path = output_directory / "redactlens-splash-dark.bmp"
    icon.save(png_path, format="PNG", optimize=True)
    icon.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    render_wizard_image(icon).save(wizard_path, format="PNG", optimize=True)
    splash = render_splash_image(icon)
    splash.save(splash_path, format="PNG", optimize=True)
    splash.convert("RGB").save(splash_bitmap_path, format="BMP")
    dark_splash = render_splash_image(icon, dark=True)
    dark_splash.save(dark_splash_path, format="PNG", optimize=True)
    dark_splash.convert("RGB").save(dark_splash_bitmap_path, format="BMP")
    return (
        png_path,
        ico_path,
        wizard_path,
        splash_path,
        splash_bitmap_path,
        dark_splash_path,
        dark_splash_bitmap_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "assets" / "branding",
    )
    args = parser.parse_args()
    for asset in generate_assets(args.output_directory):
        print(asset.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
