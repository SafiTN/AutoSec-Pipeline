import asyncio
import os
import sys
import textwrap
from pathlib import Path

import edge_tts
from moviepy import AudioFileClip, ImageClip, concatenate_videoclips
from PIL import Image, ImageDraw, ImageFont

# إضافة المسار الجذري للمشروع ليتمكن بايثون من التعرف على مجلد core بسهولة
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from core.config_loader import load_settings


class CyberMediaGenerator:
    def __init__(self, settings=None):
        """تهيئة مولد الوسائط بالاعتماد على ملف الإعدادات المركزي"""
        self.settings = settings or load_settings()
        media_cfg = self.settings["media"]

        self.output_dir = media_cfg["output_directory"]
        self.slides_dir = Path(media_cfg.get("slides_directory") or os.path.join(self.output_dir, "slides"))
        self.visual_mode = media_cfg.get("visual_mode") or "slide"
        self.voice = media_cfg["voice"]
        self.fps = int(
            media_cfg.get("video_fps")
            or media_cfg.get("fps")
            or 24
        )
        self.width = media_cfg["resolution"]["width"]
        self.height = media_cfg["resolution"]["height"]

        os.makedirs(self.output_dir, exist_ok=True)
        self.slides_dir.mkdir(parents=True, exist_ok=True)

    async def _generate_voiceover(self, text: str, audio_path: str):
        """توليد ملف الصوت من النص مجاناً باستخدام Edge-TTS"""
        communicate = edge_tts.Communicate(text, self.voice, rate="+5%")
        await communicate.save(audio_path)

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
    ) -> Path:
        """Render a clean, dark-themed cybersecurity slide for a scene using Pillow."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        w = width or self.width
        h = height or self.height

        # Background & outer card frame
        bg_color = (11, 17, 32)       # Deep navy-slate
        card_color = (17, 24, 39)     # Slightly elevated panel
        accent_cyan = (34, 211, 238)  # Cybersecurity cyan accent
        text_main = (241, 245, 249)
        text_muted = (148, 163, 184)

        img = Image.new("RGB", (w, h), color=bg_color)
        draw = ImageDraw.Draw(img)

        margin = 48
        draw.rounded_rectangle(
            [margin, margin, w - margin, h - margin],
            radius=20,
            fill=card_color,
            outline=accent_cyan,
            width=2,
        )

        # Top accent bar
        draw.rectangle([margin, margin, w - margin, margin + 8], fill=accent_cyan)

        try:
            font_header = ImageFont.truetype("arialbd.ttf", 26)
            font_title = ImageFont.truetype("arialbd.ttf", 44)
            font_body = ImageFont.truetype("arial.ttf", 30)
        except IOError:
            font_header = ImageFont.load_default()
            font_title = ImageFont.load_default()
            font_body = ImageFont.load_default()

        # Header badge: Scene number + optional CVE/Severity
        header_parts = [f"SCENE {scene_index:02d}"]
        if cve_id:
            header_parts.append(str(cve_id))
        if severity:
            header_parts.append(f"SEVERITY: {str(severity).upper()}")
        header_text = "  |  ".join(header_parts)

        draw.text((margin + 36, margin + 28), header_text, fill=accent_cyan, font=font_header)

        # Scene title
        clean_title = (title or "Technical Breakdown").strip()
        draw.text((margin + 36, margin + 72), clean_title[:90], fill=text_main, font=font_title)

        # Divider line
        draw.line(
            [(margin + 36, margin + 132), (w - margin - 36, margin + 132)],
            fill=(51, 65, 85),
            width=2,
        )

        # Visual cue label & wrapped body
        draw.text((margin + 36, margin + 156), "VISUAL CUE:", fill=accent_cyan, font=font_header)

        cue_text = (visual_cue or "Architectural diagram and key security takeaway.").strip()
        max_chars = max(35, int((w - 2 * (margin + 36)) / 14))

        lines: list[str] = []
        for paragraph in cue_text.splitlines():
            wrapped = textwrap.wrap(paragraph, width=max_chars)
            lines.extend(wrapped if wrapped else [""])

        y_cursor = margin + 200
        line_step = 42
        max_lines = max(3, (h - y_cursor - margin - 30) // line_step)

        for idx, line in enumerate(lines[:max_lines]):
            display_line = line
            if idx == max_lines - 1 and len(lines) > max_lines:
                display_line = f"{line[: max(0, len(line) - 3)]}..."
            draw.text((margin + 36, y_cursor), display_line, fill=text_muted, font=font_body)
            y_cursor += line_step

        img.save(target, format="PNG")
        return target

    def _create_cyber_slide(self, title: str, content: str, slide_path: str, is_code=False):
        """إنشاء شريحة بصرية داكنة (Dark Hacker Theme) وفق الأبعاد المحددة في الإعدادات"""
        img = Image.new("RGB", (self.width, self.height), color=(13, 17, 23))
        draw = ImageDraw.Draw(img)

        border_color = (0, 255, 136) if is_code else (56, 139, 253)
        draw.rectangle([30, 30, self.width - 30, self.height - 30], outline=border_color, width=4)

        try:
            title_font = ImageFont.truetype("arialbd.ttf", 54)
            body_font = ImageFont.truetype("consola.ttf" if is_code else "arial.ttf", 36)
        except IOError:
            title_font = ImageFont.load_default()
            body_font = ImageFont.load_default()

        draw.text((80, 70), f"> {title}", fill=border_color, font=title_font)
        draw.line([(80, 150), (self.width - 80, 150)], fill=(48, 54, 61), width=3)

        wrap_width = 75 if is_code else 65
        lines = []
        for paragraph in content.split("\n"):
            wrapped = textwrap.wrap(paragraph, width=wrap_width)
            lines.extend(wrapped if wrapped else [""])

        y_text = 200
        text_color = (165, 214, 255) if is_code else (230, 237, 243)
        for line in lines[:16]:
            draw.text((80, y_text), line, fill=text_color, font=body_font)
            y_text += 48

        img.save(slide_path)

    def build_video(
        self,
        scenes: list,
        final_video_name="cyber_episode.mp4",
        cve_id: str | None = None,
        severity: str | None = None,
    ):
        """تجميع المشاهد (صوت + صورة) في فيديو واحد متكامل"""
        video_clips = []

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
                    )
                )
            else:
                slide_path = os.path.join(self.output_dir, f"scene_{idx}.png")
                self._create_cyber_slide(
                    title=scene.get("title", ""),
                    content=visual_text,
                    slide_path=slide_path,
                    is_code=scene.get("is_code", False),
                )

            audio_clip = AudioFileClip(audio_path)
            image_clip = ImageClip(slide_path).with_duration(audio_clip.duration)
            video_clip = image_clip.with_audio(audio_clip)
            video_clips.append(video_clip)

        final_clip = concatenate_videoclips(video_clips, method="compose")
        output_path = os.path.join(self.output_dir, final_video_name)

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
    sample_scenes = [
        {
            "title": "CRITICAL VULNERABILITY ALERT: CVE-2026-XXXX",
            "visual_text": "Target: Open-Source Web Parser\nSeverity: 9.8 (Critical)\nImpact: Remote Code Execution (RCE)",
            "narration": "A new critical vulnerability has just been discovered in a widely used web parser, allowing attackers to execute remote code.",
            "is_code": False,
        },
        {
            "title": "AUTOMATED EXPLOIT / DETECTION SCRIPT",
            "visual_text": "import requests\n\ndef check_vuln(target_url):\n    payload = {'header': '{{7*7}}'}\n    res = requests.get(target_url, headers=payload)\n    return '49' in res.text",
            "narration": "Our autonomous security agent generated and verified this Python script to safely detect if your server is exposed.",
            "is_code": True,
        },
    ]

    generator = CyberMediaGenerator()
    video_file = generator.build_video(sample_scenes, "cve_analysis_ep1.mp4")
    print(f"[SUCCESS] Video generated at: {video_file}")