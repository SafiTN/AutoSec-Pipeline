"""T12: voiceover and build_video orchestration with fakes (no TTS, no ffmpeg, no real encode)."""
import asyncio
from pathlib import Path

import pytest

from modules.content_pipeline import media_generator as mg
from modules.content_pipeline.media_generator import CyberMediaGenerator


def _settings(tmp_path, mode="slide", fps=None):
    media = {
        "output_directory": str(tmp_path / "out"),
        "slides_directory": str(tmp_path / "slides"),
        "voice": "en-US-TestNeural",
        "visual_mode": mode,
        "resolution": {"width": 320, "height": 180},
    }
    if fps:
        media["video_fps"] = fps
    return {"media": media}


class FakeCommunicate:
    instances = []

    def __init__(self, text, voice, rate=None):
        self.text, self.voice, self.rate = text, voice, rate
        self.saved = None
        FakeCommunicate.instances.append(self)

    async def save(self, path):
        self.saved = path
        Path(path).write_bytes(b"fake-mp3")


def test_generate_voiceover_uses_configured_voice(tmp_path, monkeypatch):
    FakeCommunicate.instances.clear()
    monkeypatch.setattr(mg.edge_tts, "Communicate", FakeCommunicate)
    g = CyberMediaGenerator(_settings(tmp_path))
    target = tmp_path / "a.mp3"
    asyncio.run(g._generate_voiceover("Hello world", str(target)))
    inst = FakeCommunicate.instances[0]
    assert (inst.text, inst.voice, inst.saved) == ("Hello world", "en-US-TestNeural", str(target))
    assert inst.rate  # a speaking rate is set
    assert target.read_bytes() == b"fake-mp3"


def test_generate_voiceover_propagates_tts_failure(tmp_path, monkeypatch):
    class Boom(FakeCommunicate):
        async def save(self, path):
            raise ConnectionError("tts down")

    monkeypatch.setattr(mg.edge_tts, "Communicate", Boom)
    g = CyberMediaGenerator(_settings(tmp_path))
    with pytest.raises(ConnectionError):
        asyncio.run(g._generate_voiceover("x", str(tmp_path / "a.mp3")))


class FakeAudio:
    def __init__(self, path):
        self.path, self.duration = path, 1.5


class FakeVideo:
    def __init__(self, image=None, audio=None, duration=None):
        self.image, self.audio, self.duration = image, audio, duration
        self.closed = False

    def with_duration(self, d):
        self.duration = d
        return self

    def with_audio(self, a):
        self.audio = a
        return self

    def close(self):
        self.closed = True


class FakeFinal:
    def __init__(self, clips):
        self.clips, self.closed, self.write_args = clips, False, None

    def write_videofile(self, path, **kw):
        self.write_args = (path, kw)
        Path(path).write_bytes(b"fake-mp4")

    def close(self):
        self.closed = True


@pytest.fixture
def patched(monkeypatch):
    state = {"finals": [], "images": []}

    async def fake_tts(self, text, path):
        Path(path).write_bytes(b"a")

    def fake_image(path):
        state["images"].append(path)
        return FakeVideo(image=path)

    def fake_concat(clips, method=None):
        f = FakeFinal(clips)
        f.method = method
        state["finals"].append(f)
        return f

    monkeypatch.setattr(CyberMediaGenerator, "_generate_voiceover", fake_tts)
    monkeypatch.setattr(mg, "AudioFileClip", FakeAudio)
    monkeypatch.setattr(mg, "ImageClip", fake_image)
    monkeypatch.setattr(mg, "concatenate_videoclips", fake_concat)
    return state


SCENES = [
    {"title": "One", "narration": "First.", "on_screen_bullets": ["a", "b"], "key_takeaway": "k1"},
    {"title": "Two", "narration": "Second.", "visual_cue": "legacy cue"},
]


def test_build_video_slide_mode_assembles_and_closes(tmp_path, patched):
    g = CyberMediaGenerator(_settings(tmp_path, fps=12))
    out = g.build_video(SCENES, "ep.mp4", "CVE-2026-1", "HIGH")
    assert out == str(Path(g.output_dir) / "ep.mp4") and Path(out).read_bytes() == b"fake-mp4"
    final = patched["finals"][0]
    assert len(final.clips) == 2 and final.method == "compose"
    path, kw = final.write_args
    assert kw["fps"] == 12 and kw["codec"] == "libx264" and kw["audio_codec"] == "aac"
    assert all(c.closed for c in final.clips) and final.closed
    assert all(c.duration == 1.5 and c.audio.path.endswith(f"scene_{i}.mp3")
               for i, c in enumerate(final.clips, 1))
    assert len(patched["images"]) == 2 and all(Path(p).is_file() for p in patched["images"])
    assert Path(patched["images"][0]).parent == Path(tmp_path / "slides")


def test_build_video_legacy_mode_writes_png_in_output_dir(tmp_path, patched):
    g = CyberMediaGenerator(_settings(tmp_path, mode="legacy"))
    g.build_video(SCENES, "ep.mp4", "CVE-2026-1", "HIGH")
    assert [Path(p).name for p in patched["images"]] == ["scene_1.png", "scene_2.png"]
    assert all(Path(p).parent == Path(g.output_dir) for p in patched["images"])


def test_build_video_removes_stale_output_before_render(tmp_path, patched, monkeypatch):
    g = CyberMediaGenerator(_settings(tmp_path))
    stale = Path(g.output_dir) / "ep.mp4"
    stale.write_bytes(b"stale")
    seen = {}
    orig = FakeFinal.write_videofile

    def spy(self, path, **kw):
        seen["existed"] = Path(path).exists()
        orig(self, path, **kw)

    monkeypatch.setattr(FakeFinal, "write_videofile", spy)
    g.build_video(SCENES[:1], "ep.mp4", "CVE-2026-1", "HIGH")
    assert seen["existed"] is False


def test_build_video_stale_file_not_left_when_render_fails(tmp_path, patched, monkeypatch):
    g = CyberMediaGenerator(_settings(tmp_path))
    stale = Path(g.output_dir) / "ep.mp4"
    stale.write_bytes(b"stale")

    def fail(self, path, **kw):
        raise OSError("ffmpeg missing")

    monkeypatch.setattr(FakeFinal, "write_videofile", fail)
    with pytest.raises(OSError):
        g.build_video(SCENES[:1], "ep.mp4", "CVE-2026-1", "HIGH")
    assert not stale.exists()


def test_build_video_name_cannot_escape_output_dir(tmp_path, patched):
    g = CyberMediaGenerator(_settings(tmp_path))
    out = g.build_video(SCENES[:1], "../../evil.mp4", "CVE-2026-1", "HIGH")
    assert Path(out).parent == Path(g.output_dir) and Path(out).name == "evil.mp4"
    assert not (tmp_path / "evil.mp4").exists()


def test_build_video_tts_failure_aborts_without_video(tmp_path, monkeypatch, patched):
    async def boom(self, text, path):
        raise ConnectionError("tts down")

    monkeypatch.setattr(CyberMediaGenerator, "_generate_voiceover", boom)
    g = CyberMediaGenerator(_settings(tmp_path))
    with pytest.raises(ConnectionError):
        g.build_video(SCENES, "ep.mp4", "CVE-2026-1", "HIGH")
    assert patched["finals"] == [] and not (Path(g.output_dir) / "ep.mp4").exists()


def test_build_video_long_title_and_bullets_render_real_slide(tmp_path, patched):
    g = CyberMediaGenerator(_settings(tmp_path))
    scene = {"title": "T" * 600, "narration": "n.", "on_screen_bullets": ["b " * 200] * 5,
             "key_takeaway": "k " * 300}
    g.build_video([scene], "ep.mp4", "CVE-2026-1", None)
    assert Path(patched["images"][0]).stat().st_size > 0
