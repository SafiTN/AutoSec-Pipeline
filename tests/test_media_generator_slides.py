"""T08 slide redesign tests: fonts, wrapping, layout, badges. No network/TTS/encode."""
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.content_pipeline import media_generator as mg  # noqa: E402
from modules.content_pipeline.media_generator import (  # noqa: E402
    CyberMediaGenerator, load_font, severity_badge, wrap_text,
)

LONG = "word " * 80
LONG_TOKEN = "https://example.com/" + "a" * 200


def make_settings(tmp_path, width=1280, height=720, slide=None):
    media = {
        "output_directory": str(tmp_path / "out"),
        "slides_directory": str(tmp_path / "slides"),
        "voice": "en-US-GuyNeural",
        "visual_mode": "slide",
        "resolution": {"width": width, "height": height},
    }
    if slide is not None:
        media["slide"] = slide
    return {"media": media}


@pytest.fixture
def gen(tmp_path):
    return CyberMediaGenerator(make_settings(tmp_path))


@pytest.fixture
def spy(monkeypatch):
    calls = []
    orig = ImageDraw.ImageDraw.text

    def _text(self, xy, text, *a, **kw):
        calls.append((xy, text, kw.get("font")))
        return orig(self, xy, text, *a, **kw)

    monkeypatch.setattr(ImageDraw.ImageDraw, "text", _text)
    return calls


# ---------- fonts ----------
def test_bundled_fonts_exist_and_load():
    for name in ("Inter-Regular.ttf", "Inter-Bold.ttf"):
        assert (ROOT / "assets" / "fonts" / name).is_file()
        font = load_font(f"assets/fonts/{name}", 24)
        assert isinstance(font, ImageFont.FreeTypeFont)
        assert font.getlength("CVE-2026-0001") > 0


def test_missing_font_falls_back_with_warning(caplog):
    with caplog.at_level("WARNING"):
        font = load_font("assets/fonts/does-not-exist.ttf", 24)
    assert font.getlength("abc") > 0
    assert "missing" in caplog.text.lower()


def test_empty_font_path_falls_back():
    assert load_font("", 20).getlength("x") > 0
    assert load_font(None, 20).getlength("x") > 0


def test_render_with_missing_fonts_still_works(tmp_path):
    slide = {"fonts": {"regular": "nope/a.ttf", "bold": "nope/b.ttf", "mono": ""}}
    g = CyberMediaGenerator(make_settings(tmp_path, slide=slide))
    p = g.render_smart_scene_slide(tmp_path / "s.png", 1, "Title", "cue",
                                   bullets=["a"], key_takeaway="t")
    assert p.is_file()


# ---------- wrap_text ----------
@pytest.mark.parametrize("size,maxw", [(30, 400), (18, 250), (46, 900)])
def test_wrap_lines_fit(size, maxw):
    font = load_font("assets/fonts/Inter-Regular.ttf", size)
    lines = wrap_text(LONG, font, maxw)
    assert len(lines) > 1
    assert all(font.getlength(l) <= maxw for l in lines)


def test_wrap_pure_and_deterministic():
    font = load_font("assets/fonts/Inter-Regular.ttf", 28)
    assert wrap_text(LONG, font, 500) == wrap_text(LONG, font, 500)


def test_wrap_breaks_overlong_token():
    font = load_font("assets/fonts/Inter-Regular.ttf", 28)
    lines = wrap_text(LONG_TOKEN, font, 300)
    assert len(lines) > 1
    assert all(font.getlength(l) <= 300 for l in lines)
    assert "".join(lines) == LONG_TOKEN


@pytest.mark.parametrize("maxw", [300, 600])
def test_wrap_max_lines_ellipsis(maxw):
    font = load_font("assets/fonts/Inter-Regular.ttf", 28)
    lines = wrap_text(LONG, font, maxw, max_lines=2)
    assert len(lines) == 2
    assert lines[-1].endswith("...")
    assert all(font.getlength(l) <= maxw for l in lines)


def test_wrap_no_ellipsis_when_fits():
    font = load_font("assets/fonts/Inter-Regular.ttf", 28)
    assert wrap_text("short text", font, 600, max_lines=2) == ["short text"]


def test_wrap_empty_and_none():
    font = load_font("assets/fonts/Inter-Regular.ttf", 28)
    assert wrap_text("", font, 300) == [""]
    assert wrap_text(None, font, 300) == [""]


# ---------- rendering ----------
@pytest.mark.parametrize("w,h", [(1280, 720), (960, 540), (1920, 1080)])
def test_png_created_with_size(tmp_path, w, h):
    g = CyberMediaGenerator(make_settings(tmp_path, w, h))
    p = g.render_smart_scene_slide(tmp_path / "x" / "a.png", 2, "Title", "",
                                   cve_id="CVE-2026-1", severity="HIGH",
                                   bullets=["one"], key_takeaway="take")
    with Image.open(p) as im:
        assert im.size == (w, h)


def test_legacy_three_key_scene_renders_visual_cue_as_body(gen, tmp_path, spy):
    p = gen.render_smart_scene_slide(tmp_path / "l.png", 1, "Legacy", "Old visual cue body")
    assert p.is_file()
    texts = " ".join(t for _, t, _ in spy)
    assert "Old visual cue body" in texts


def test_bullets_capped_at_three(gen, tmp_path, spy):
    gen.render_smart_scene_slide(tmp_path / "b.png", 2, "T", "cue",
                                 bullets=["B1", "B2", "B3", "B4", "B5"])
    texts = [t for _, t, _ in spy]
    assert all(b in texts for b in ("B1", "B2", "B3"))
    assert "B4" not in texts and "B5" not in texts


def test_visual_cue_ignored_when_bullets_present(gen, tmp_path, spy):
    gen.render_smart_scene_slide(tmp_path / "b.png", 2, "T", "SECRETCUE", bullets=["B1"])
    assert "SECRETCUE" not in [t for _, t, _ in spy]


def test_visual_cue_label_never_drawn(gen, tmp_path, spy):
    gen.render_smart_scene_slide(tmp_path / "1.png", 1, "T", "cue")
    gen.render_smart_scene_slide(tmp_path / "2.png", 2, "Patch now", "cue",
                                 bullets=["a"], key_takeaway="k")
    gen.visual_mode = "other"
    gen._create_cyber_slide("T", "content", str(tmp_path / "3.png"))
    gen._create_cyber_slide("T", "content", str(tmp_path / "4.png"), is_code=True)
    assert spy
    assert not any("visual cue" in t.lower() for _, t, _ in spy)


def test_severity_badge_mapping():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        label, color = severity_badge(sev)
        assert label == sev and color == mg.SEVERITY_COLORS[sev]
    assert severity_badge(" high ")[0] == "HIGH"
    for bad in (None, "", "weird", "N/A"):
        label, color = severity_badge(bad)
        assert label == "NOT YET SPECIFIED"
        assert color == mg.NEUTRAL_BADGE


def test_badge_text_drawn(gen, tmp_path, spy):
    gen.render_smart_scene_slide(tmp_path / "a.png", 1, "T", "", cve_id="CVE-2026-9999",
                                 severity="critical")
    texts = [t for _, t, _ in spy]
    assert "CVE-2026-9999" in texts
    assert "SEVERITY: CRITICAL" in texts


def test_unknown_severity_and_missing_cve_not_invented(gen, tmp_path, spy):
    gen.render_smart_scene_slide(tmp_path / "a.png", 1, "T", "")
    joined = " ".join(t for _, t, _ in spy)
    assert "NOT YET SPECIFIED" in joined
    assert "not yet specified" in joined
    assert "CVE-20" not in joined


@pytest.mark.parametrize("w,h", [(1280, 720), (960, 540)])
def test_no_text_overflows_card(tmp_path, spy, w, h):
    g = CyberMediaGenerator(make_settings(tmp_path, w, h))
    scale = min(w / 1280, h / 720)
    margin = int(48 * scale)
    g.render_smart_scene_slide(
        tmp_path / "o.png", 2, LONG + LONG_TOKEN, "",
        cve_id="CVE-2026-12345", severity="HIGH",
        bullets=[LONG, LONG_TOKEN, LONG, "extra"], key_takeaway=LONG)
    assert spy
    for (x, y), text, font in spy:
        l, t, r, b = font.getbbox(text)
        assert x + l >= margin, text
        assert x + r <= w - margin, text
        assert y + b <= h - margin, text


def test_build_video_passes_scene_keys(tmp_path, monkeypatch):
    g = CyberMediaGenerator(make_settings(tmp_path))
    captured = {}

    async def fake_tts(text, path):
        Path(path).write_bytes(b"")

    def fake_render(**kw):
        captured.update(kw)
        raise RuntimeError("stop")

    monkeypatch.setattr(g, "_generate_voiceover", fake_tts)
    monkeypatch.setattr(g, "render_smart_scene_slide", fake_render)
    scene = {"title": "T", "narration": "n", "visual_cue": "v",
             "on_screen_bullets": ["a"], "key_takeaway": "k"}
    with pytest.raises(RuntimeError):
        g.build_video([scene], "x.mp4", "CVE-2026-1", "HIGH")
    assert captured["bullets"] == ["a"]
    assert captured["key_takeaway"] == "k"
    assert captured["cve_id"] == "CVE-2026-1" and captured["severity"] == "HIGH"
