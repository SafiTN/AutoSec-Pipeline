import asyncio
import logging
import os
import re
import sys
from pathlib import Path

import edge_tts
from moviepy import AudioFileClip, ImageClip, concatenate_videoclips
from PIL import Image, ImageDraw, ImageFont

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from core.config_loader import load_settings, resolve_project_path

logger = logging.getLogger(__name__)

ELLIPSIS = "..."
NOT_SPECIFIED = "not yet specified"

# Defaults mirror config/settings.yaml (media.slide); settings override them.
DEFAULT_SLIDE_CFG = {
    "fonts": {
        "regular": "assets/fonts/Inter-Regular.ttf",
        "bold": "assets/fonts/Inter-Bold.ttf",
        "mono": "",
    },
    "sizes": {"title": 46, "body": 30, "header": 22, "badge": 22, "takeaway": 28},
    "min_font_size": 18,
    "margin": 48,
    "max_bullets": 3,
    "sample_label": "SAMPLE",
}

BG = (11, 17, 32)
CARD = (17, 24, 39)
ACCENT = (34, 211, 238)
TEXT_MAIN = (241, 245, 249)
TEXT_MUTED = (148, 163, 184)
DIVIDER = (51, 65, 85)
CALLOUT_BG = (8, 47, 73)
NEUTRAL_BADGE = (71, 85, 105)

SEVERITY_COLORS = {
    "CRITICAL": (220, 38, 38),
    "HIGH": (234, 88, 12),
    "MEDIUM": (202, 138, 4),
    "LOW": (22, 163, 74),
}
_CHECKLIST_RE = re.compile(r"mitigat|patch|fix|remediat|recommend|protect|defen|what to do", re.I)


def load_font(path: str | None, size: int):
    """Single place that loads fonts: bundled file by project-relative path,
    falling back to Pillow's built-in font (with a warning) if it is missing."""
    if path:
        resolved = resolve_project_path(path)
        try:
            return ImageFont.truetype(str(resolved), size)
        except OSError:
            logger.warning("Bundled font missing or unreadable: %s; using Pillow default", resolved)
    return ImageFont.load_default(size)


def _text_width(font, text: str) -> float:
    return font.getlength(text)


def _line_height(font) -> int:
    box = font.getbbox("Ag")
    return int(box[3] - box[1])


def _break_token(token: str, font, max_width_px: int) -> list[str]:
    """Split a single over-long token into pieces that fit max_width_px."""
    pieces, cur = [], ""
    for ch in token:
        if cur and _text_width(font, cur + ch) > max_width_px:
            pieces.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        pieces.append(cur)
    return pieces


def _ellipsize(line: str, font, max_width_px: int) -> str:
    line = line.rstrip()
    while line and _text_width(font, line + ELLIPSIS) > max_width_px:
        line = line[:-1].rstrip()
    return line + ELLIPSIS


def wrap_text(text: str, font, max_width_px: int, max_lines: int | None = None) -> list[str]:
    """Pixel-based word wrap. Over-long tokens are broken; when more than
    max_lines would be needed the last line is truncated with an ellipsis."""
    lines: list[str] = []
    for paragraph in str(text or "").splitlines() or [""]:
        cur = ""
        for word in paragraph.split():
            if _text_width(font, word) <= max_width_px:
                tokens = [word]
            else:
                tokens = _break_token(word, font, max_width_px)
            for token in tokens:
                candidate = f"{cur} {token}" if cur else token
                if _text_width(font, candidate) <= max_width_px:
                    cur = candidate
                else:
                    if cur:
                        lines.append(cur)
                    cur = token
        lines.append(cur)
    if max_lines is not None and len(lines) > max_lines:
        lines = lines[:max_lines]
        if max_lines > 0:
            lines[-1] = _ellipsize(lines[-1], font, max_width_px)
    return lines


def fit_text(
    text: str,
    font_path: str | None,
    size: int,
    min_size: int,
    max_width_px: int,
    max_height_px: int,
    spacing: float = 1.35,
):
    """Shrink the font until the wrapped text fits the box; truncate with an
    ellipsis at min_size. Returns (font, lines, line_step)."""
    cur = max(size, min_size)
    while True:
        font = load_font(font_path, cur)
        step = max(1, int(_line_height(font) * spacing))
        max_lines = max(1, max_height_px // step)
        if len(wrap_text(text, font, max_width_px)) <= max_lines or cur <= min_size:
            return font, wrap_text(text, font, max_width_px, max_lines), step
        cur -= 2


def severity_badge(severity: str | None) -> tuple[str, tuple[int, int, int]]:
    """Map severity to (label, colour). Unknown/missing is never invented."""
    key = str(severity or "").strip().upper()
    if key in SEVERITY_COLORS:
        return key, SEVERITY_COLORS[key]
    return NOT_SPECIFIED.upper(), NEUTRAL_BADGE


class CyberMediaGenerator:
    def __init__(self, settings=None):
        """Initialise the media generator from the central settings file."""
        self.settings = settings or load_settings()
        media_cfg = self.settings["media"]

        self.output_dir = str(resolve_project_path(media_cfg["output_directory"]))
        slides_cfg_dir = media_cfg.get("slides_directory")
        self.slides_dir = (
            Path(resolve_project_path(slides_cfg_dir)) if slides_cfg_dir else Path(self.output_dir) / "slides"
        )
        self.visual_mode = media_cfg.get("visual_mode") or "slide"
        self.voice = media_cfg["voice"]
        self.fps = int(media_cfg.get("video_fps") or media_cfg.get("fps") or 24)
        self.width = media_cfg["resolution"]["width"]
        self.height = media_cfg["resolution"]["height"]

        slide_cfg = media_cfg.get("slide") or {}
        self.slide_cfg = {}
        for key, default in DEFAULT_SLIDE_CFG.items():
            if isinstance(default, dict):
                self.slide_cfg[key] = {**default, **(slide_cfg.get(key) or {})}
            else:
                self.slide_cfg[key] = slide_cfg.get(key, default)

        os.makedirs(self.output_dir, exist_ok=True)
        self.slides_dir.mkdir(parents=True, exist_ok=True)

    async def _generate_voiceover(self, text: str, audio_path: str):
        """Generate the voiceover file with Edge-TTS."""
        communicate = edge_tts.Communicate(text, self.voice, rate="+5%")
        await communicate.save(audio_path)

    def _font_path(self, role: str) -> str | None:
        fonts = self.slide_cfg["fonts"]
        return fonts.get(role) or fonts.get("regular")

    def _font(self, role: str, size_key: str, scale: float = 1.0):
        px = self.slide_cfg["sizes"][size_key]
        return load_font(self._font_path(role), max(8, int(px * scale)))

    @staticmethod
    def _pick_layout(scene_index: int, title: str, bullets: list[str]) -> str:
        if bullets and _CHECKLIST_RE.search(title or ""):
            return "checklist"
        if scene_index == 1:
            return "title"
        return "bullets"

    def render_smart_scene_slide(
        self,
        output_path: Path,
        scene_index: int,
        title: str,
        visual_cue: str,
        width: int | None = None,
        height: int | None = None,
        cve_id: str | None = None,
        severity: str | None = None,
        bullets: list[str] | None = None,
        key_takeaway: str | None = None,
        layout: str | None = None,
        is_sample: bool = False,
    ) -> Path:
        """Render a viewer-facing slide: title, up to max_bullets bullets,
        takeaway callout, CVE id and severity badge. visual_cue is only the
        legacy fallback body when no bullets are given and is never labelled."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        w = width or self.width
        h = height or self.height
        scale = min(w / 1280, h / 720)
        cfg = self.slide_cfg
        sizes = cfg["sizes"]
        min_size = max(8, int(cfg["min_font_size"] * scale))
        margin = int(cfg["margin"] * scale)
        pad = int(36 * scale)

        clean_bullets = [str(b).strip() for b in (bullets or []) if str(b or "").strip()]
        clean_bullets = clean_bullets[: int(cfg["max_bullets"])]
        takeaway = str(key_takeaway or "").strip()
        clean_title = str(title or "").strip() or "Technical Breakdown"
        legacy_body = "" if clean_bullets else str(visual_cue or "").strip()
        layout = layout or self._pick_layout(scene_index, clean_title, clean_bullets)

        img = Image.new("RGB", (w, h), color=BG)
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle(
            [margin, margin, w - margin, h - margin], radius=int(20 * scale), fill=CARD, outline=ACCENT, width=2
        )
        draw.rectangle([margin, margin, w - margin, margin + int(8 * scale)], fill=ACCENT)

        left = margin + pad
        right = w - margin - pad
        inner_w = right - left
        bottom = h - margin - pad

        # Header row: CVE badge + severity badge (left), scene number (right)
        badge_font = self._font("bold", "badge", scale)
        y = margin + int(28 * scale)
        x = left
        bx, by = int(14 * scale), int(8 * scale)
        badge_h = 0
        cve_text = str(cve_id).strip() if cve_id else f"CVE {NOT_SPECIFIED}"
        sev_text, sev_color = severity_badge(severity)
        for text, fill, fg in (
            (cve_text, None, ACCENT),
            (f"SEVERITY: {sev_text}", sev_color, (255, 255, 255)),
        ):
            avail = right - x - 2 * bx
            if avail <= 0:
                break
            label = wrap_text(text, badge_font, avail, max_lines=1)[0]
            bbox = badge_font.getbbox(label)
            bw = int(_text_width(badge_font, label)) + 2 * bx
            bh = _line_height(badge_font) + 2 * by
            draw.rounded_rectangle(
                [x, y, x + bw, y + bh], radius=bh // 2, fill=fill, outline=ACCENT if fill is None else None, width=2
            )
            draw.text((x + bx, y + by - bbox[1]), label, fill=fg, font=badge_font)
            x += bw + int(12 * scale)
            badge_h = max(badge_h, bh)
        scene_font = self._font("regular", "header", scale)
        scene_label = f"{scene_index:02d}"
        draw.text((right - _text_width(scene_font, scene_label), y + by), scene_label, fill=TEXT_MUTED, font=scene_font)
        y += badge_h + int(22 * scale)

        # Takeaway callout reserves space at the bottom
        callout_top = bottom
        callout = None
        if takeaway:
            c_pad = int(16 * scale)
            t_font, t_lines, t_step = fit_text(
                takeaway,
                self._font_path("bold"),
                int(sizes["takeaway"] * scale),
                min_size,
                inner_w - 2 * pad,
                int(h * 0.2),
            )
            callout_top = bottom - (len(t_lines) * t_step + 2 * c_pad)
            callout = (t_font, t_lines, t_step, c_pad)

        # Title
        is_card = layout == "title"
        title_size = int(sizes["title"] * scale * (1.25 if is_card else 1.0))
        t_max_h = int((h - y) * (0.5 if is_card else 0.28))
        title_font, title_lines, title_step = fit_text(
            clean_title, self._font_path("bold"), title_size, min_size, inner_w, t_max_h, spacing=1.2
        )
        for line in title_lines:
            draw.text((left, y), line, fill=TEXT_MAIN, font=title_font)
            y += title_step
        y += int(8 * scale)
        draw.line([(left, y), (right, y)], fill=DIVIDER, width=2)
        y += int(24 * scale)

        # Body: bullets / checklist items / legacy paragraph
        body_bottom = callout_top - int(20 * scale)
        items = clean_bullets or ([legacy_body] if legacy_body else [])
        if items:
            marker_w = int(44 * scale) if clean_bullets else 0
            gap = int(14 * scale)
            per_item_h = max(1, (body_bottom - y) // len(items) - gap)
            for item in items:
                b_font, b_lines, b_step = fit_text(
                    item,
                    self._font_path("regular"),
                    int(sizes["body"] * scale),
                    min_size,
                    inner_w - marker_w,
                    per_item_h,
                )
                if clean_bullets:
                    cy = y + b_step // 2
                    r = max(4, int(9 * scale))
                    if layout == "checklist":
                        box = [left, cy - r, left + 2 * r, cy + r]
                        draw.rounded_rectangle(box, radius=3, outline=ACCENT, width=3)
                        draw.line(
                            [(box[0] + r // 2, cy), (left + r, cy + r // 2), (box[2] - r // 3, cy - r // 2)],
                            fill=ACCENT,
                            width=3,
                        )
                    else:
                        draw.ellipse([left, cy - r // 2, left + r, cy + r // 2], fill=ACCENT)
                for line in b_lines:
                    draw.text((left + marker_w, y), line, fill=TEXT_MAIN if clean_bullets else TEXT_MUTED, font=b_font)
                    y += b_step
                y += gap

        if callout:
            t_font, t_lines, t_step, c_pad = callout
            draw.rounded_rectangle(
                [left, callout_top, right, bottom], radius=int(12 * scale), fill=CALLOUT_BG, outline=ACCENT, width=2
            )
            bar = max(4, int(6 * scale))
            draw.rectangle([left, callout_top + 6, left + bar, bottom - 6], fill=ACCENT)
            ty = callout_top + c_pad
            for line in t_lines:
                draw.text((left + bar + pad // 2, ty), line, fill=TEXT_MAIN, font=t_font)
                ty += t_step

        if is_sample:
            # Bottom-right, inside the card's bottom padding band (below the
            # callout/bullets, within margins), so nothing else is overlapped.
            self._draw_sample_marker(draw, scale, left, right, bottom, h - margin)

        img.save(target, format="PNG")
        return target

    def _draw_sample_marker(self, draw, scale: float, left: int, right: int, band_top: int, band_bottom: int) -> None:
        """Draw the sample pill (media.slide.sample_label) right-aligned in the given band."""
        label = str(self.slide_cfg.get("sample_label") or "SAMPLE")
        s_font = self._font("bold", "badge", scale)
        sx, sy = int(12 * scale), int(2 * scale)
        max_w = max(1, right - left - 2 * sx)
        label = wrap_text(label, s_font, max_w, max_lines=1)[0]
        bbox = s_font.getbbox(label)
        pw = int(_text_width(s_font, label)) + 2 * sx
        ph = min(_line_height(s_font) + 2 * sy, max(1, band_bottom - band_top - 2))
        py = band_top + max(0, (band_bottom - band_top - ph) // 2)
        draw.rounded_rectangle([right - pw, py, right, py + ph], radius=ph // 2, fill=SEVERITY_COLORS["CRITICAL"])
        draw.text((right - pw + sx, py + sy - bbox[1]), label, fill=(255, 255, 255), font=s_font)

    def _create_cyber_slide(self, title: str, content: str, slide_path: str, is_code=False, is_sample: bool = False):
        """Legacy dark slide (non-"slide" visual modes), sized from settings."""
        w, h = self.width, self.height
        img = Image.new("RGB", (w, h), color=(13, 17, 23))
        draw = ImageDraw.Draw(img)

        border_color = (0, 255, 136) if is_code else (56, 139, 253)
        draw.rectangle([30, 30, w - 30, h - 30], outline=border_color, width=4)

        title_font = self._font("bold", "title")
        body_font = self._font("mono" if is_code else "regular", "body")
        max_w = w - 160

        title_line = wrap_text(f"> {title}", title_font, max_w, max_lines=1)[0]
        draw.text((80, 70), title_line, fill=border_color, font=title_font)
        draw.line([(80, 150), (w - 80, 150)], fill=(48, 54, 61), width=3)

        step = max(1, int(_line_height(body_font) * 1.4))
        max_lines = max(1, (h - 200 - 60) // step)
        y_text = 200
        text_color = (165, 214, 255) if is_code else (230, 237, 243)
        for line in wrap_text(content or "", body_font, max_w, max_lines=max_lines):
            draw.text((80, y_text), line, fill=text_color, font=body_font)
            y_text += step

        if is_sample:
            # Band between the last text line limit (h - 60) and the border (h - 30).
            self._draw_sample_marker(draw, 1.0, 80, w - 60, h - 60, h - 30)

        img.save(slide_path)

    def build_video(
        self,
        scenes: list,
        final_video_name="cyber_episode.mp4",
        cve_id: str | None = None,
        severity: str | None = None,
        is_sample: bool = False,
    ):
        """Assemble scenes (audio + image) into a single video.
        is_sample=True draws a visible sample marker on every slide."""
        video_clips = []
        output_path = os.path.join(self.output_dir, Path(final_video_name).name)
        if os.path.isfile(output_path):
            # Remove a stale file so a failed render cannot pass the caller's isfile check.
            os.remove(output_path)

        for idx, scene in enumerate(scenes, start=1):
            audio_path = os.path.join(self.output_dir, f"scene_{idx}.mp3")
            asyncio.run(self._generate_voiceover(scene["narration"], audio_path))

            visual_text = scene.get("visual_cue") or scene.get("visual_text") or ""

            if self.visual_mode == "slide":
                slide_path = str(
                    self.render_smart_scene_slide(
                        output_path=self.slides_dir / f"scene_{idx:02d}.png",
                        scene_index=idx,
                        title=scene.get("title", ""),
                        visual_cue=visual_text,
                        width=self.width,
                        height=self.height,
                        cve_id=cve_id or scene.get("cve_id"),
                        severity=severity or scene.get("severity"),
                        bullets=scene.get("on_screen_bullets"),
                        key_takeaway=scene.get("key_takeaway"),
                        is_sample=is_sample,
                    )
                )
            else:
                slide_path = os.path.join(self.output_dir, f"scene_{idx}.png")
                self._create_cyber_slide(
                    title=scene.get("title", ""),
                    content=visual_text,
                    slide_path=slide_path,
                    is_code=scene.get("is_code", False),
                    is_sample=is_sample,
                )

            audio_clip = AudioFileClip(audio_path)
            image_clip = ImageClip(slide_path).with_duration(audio_clip.duration)
            video_clip = image_clip.with_audio(audio_clip)
            video_clips.append(video_clip)

        final_clip = concatenate_videoclips(video_clips, method="compose")

        final_clip.write_videofile(
            output_path,
            fps=self.fps,
            codec="libx264",
            audio_codec="aac",
            logger=None,
        )

        for clip in video_clips:
            clip.close()
        final_clip.close()

        return output_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_scenes = [
        {
            "title": "Critical vulnerability alert",
            "on_screen_bullets": ["Affected component: open-source web parser", "Impact: remote code execution"],
            "key_takeaway": "Patch as soon as a fixed version is available.",
            "narration": "A new critical vulnerability has been reported in a widely used web parser.",
        },
    ]
    generator = CyberMediaGenerator()
    print(
        f"Video generated at: {generator.build_video(sample_scenes, 'cve_analysis_ep1.mp4', 'CVE-2026-0000', 'CRITICAL')}"
    )
