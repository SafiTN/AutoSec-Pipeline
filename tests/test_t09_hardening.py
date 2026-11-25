"""T09 security-fix tests: sample marker, render_error, stale file, path hardening,
__main__ exit codes. Fully offline: no moviepy encode, no TTS, no network."""

import json
import runpy
from pathlib import Path

import pytest
from PIL import ImageDraw

import main
from modules.content_pipeline import media_generator as mg
from modules.content_pipeline.media_generator import CyberMediaGenerator

ROOT = Path(__file__).resolve().parents[1]


def make_settings(tmp_path, visual_mode="slide", slide=None):
    media = {
        "output_directory": str(tmp_path / "out"),
        "slides_directory": str(tmp_path / "slides"),
        "voice": "en-US-GuyNeural",
        "visual_mode": visual_mode,
        "resolution": {"width": 1280, "height": 720},
    }
    if slide is not None:
        media["slide"] = slide
    return {"media": media}


@pytest.fixture
def spy(monkeypatch):
    calls = []
    orig = ImageDraw.ImageDraw.text

    def _text(self, xy, text, *a, **kw):
        calls.append(text)
        return orig(self, xy, text, *a, **kw)

    monkeypatch.setattr(ImageDraw.ImageDraw, "text", _text)
    return calls


# ---------- sample marker ----------
def test_legacy_slide_sample_differs_and_draws_label(tmp_path, spy):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    a, b = tmp_path / "a.png", tmp_path / "b.png"
    g._create_cyber_slide("T", "content", str(a), is_sample=False)
    assert "SAMPLE" not in spy
    g._create_cyber_slide("T", "content", str(b), is_sample=True)
    assert "SAMPLE" in spy
    assert a.read_bytes() != b.read_bytes()


@pytest.mark.parametrize("label", ["", None])
def test_empty_sample_label_still_draws_sample(tmp_path, spy, label):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    g.slide_cfg["sample_label"] = label
    g._create_cyber_slide("T", "c", str(tmp_path / "x.png"), is_sample=True)
    assert "SAMPLE" in spy


def test_smart_slide_sample_draws_label(tmp_path, spy):
    g = CyberMediaGenerator(make_settings(tmp_path))
    g.render_smart_scene_slide(tmp_path / "s.png", 1, "T", "cue", bullets=["a"], key_takeaway="k", is_sample=True)
    assert "SAMPLE" in spy


def test_custom_sample_label_used(tmp_path, spy):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    g.slide_cfg["sample_label"] = "DEMO"
    g._create_cyber_slide("T", "c", str(tmp_path / "x.png"), is_sample=True)
    assert "DEMO" in spy and "SAMPLE" not in spy


# ---------- build_video with stubbed moviepy ----------
class _Clip:
    duration = 1.0
    produce = True

    def __init__(self, *a, **k):
        pass

    def with_duration(self, d):
        return self

    def with_audio(self, a):
        return self

    def close(self):
        pass

    def write_videofile(self, path, **k):
        if _Clip.produce:
            Path(path).write_bytes(b"video")


@pytest.fixture
def stub_media(monkeypatch):
    _Clip.produce = True

    async def _voice(self, text, path):
        Path(path).write_bytes(b"mp3")

    monkeypatch.setattr(CyberMediaGenerator, "_generate_voiceover", _voice)
    monkeypatch.setattr(mg, "AudioFileClip", _Clip)
    monkeypatch.setattr(mg, "ImageClip", _Clip)
    monkeypatch.setattr(mg, "concatenate_videoclips", lambda clips, method=None: _Clip())
    return _Clip


SCENES = [{"title": "t", "narration": "n", "visual_cue": "v"}]


def test_build_video_forwards_is_sample_in_legacy_mode(tmp_path, stub_media, monkeypatch):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    Path(g.output_dir).mkdir(parents=True, exist_ok=True)
    seen = []
    monkeypatch.setattr(g, "_create_cyber_slide", lambda **kw: seen.append(kw.get("is_sample")))
    g.build_video(SCENES, "v.mp4", is_sample=True)
    g.build_video(SCENES, "v.mp4")
    assert seen == [True, False]


def test_build_video_forwards_is_sample_in_slide_mode(tmp_path, stub_media, monkeypatch):
    g = CyberMediaGenerator(make_settings(tmp_path))
    Path(g.output_dir).mkdir(parents=True, exist_ok=True)
    seen = []
    monkeypatch.setattr(
        g, "render_smart_scene_slide", lambda **kw: seen.append(kw.get("is_sample")) or tmp_path / "s.png"
    )
    g.build_video(SCENES, "v.mp4", is_sample=True)
    assert seen == [True]


def test_build_video_deletes_stale_file_before_render(tmp_path, stub_media, monkeypatch):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    out = Path(g.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stale = out / "v.mp4"
    stale.write_bytes(b"stale")
    stub_media.produce = False  # render "fails" silently
    monkeypatch.setattr(g, "_create_cyber_slide", lambda **kw: None)
    g.build_video(SCENES, "v.mp4")
    assert not stale.exists()


def test_build_video_neutralises_dotdot_in_name(tmp_path, stub_media, monkeypatch):
    g = CyberMediaGenerator(make_settings(tmp_path, "legacy"))
    Path(g.output_dir).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(g, "_create_cyber_slide", lambda **kw: None)
    result = g.build_video(SCENES, "../../evil/../x.mp4")
    assert Path(result).parent == Path(g.output_dir)
    assert Path(result).name == "x.mp4"
    assert not (tmp_path / "x.mp4").exists()


# ---------- main._video_filename ----------
@pytest.mark.parametrize(
    "name,sample,expected",
    [
        ("../../evil.mp4", False, "evil.mp4"),
        ("sub/dir/a.mp4", True, "sample_a.mp4"),
        ("..", False, ""),
    ],
)
def test_video_filename_strips_directories(name, sample, expected):
    out = main._video_filename({"paths": {"default_video_filename": name}}, sample)
    assert "/" not in out and "\\" not in out and ".." not in out.replace("sample_", "") or out == ".."
    if expected:
        assert out == expected


def test_video_filename_default():
    assert main._video_filename({}, False) == "cyber_episode.mp4"
    assert main._video_filename({}, True) == "sample_cyber_episode.mp4"


# ---------- render_error in manifest ----------
class _Fetcher:
    def __init__(self, settings=None):
        pass

    def fetch_latest_cves(self, limit=3):
        return [{"cve_id": "CVE-2026-1", "severity": "HIGH", "cvss_score": 8.0, "summary": "s", "is_sample": False}]


class _Writer:
    def __init__(self, settings=None):
        pass

    def generate_episode_script(self, advisory, max_scenes=3):
        return {
            "episode_title": "T",
            "cve_id": advisory["cve_id"],
            "scenes": [{"title": "s", "narration": "n", "visual_cue": "c"}],
        }


def _settings(tmp_path):
    return {
        "nvd": {"max_results": 5},
        "paths": {
            "output_dir": str(tmp_path / "output"),
            "default_video_filename": "v.mp4",
            "manifest_filename": "m.json",
            "covered_cves_filename": "c.json",
        },
    }


def _run(monkeypatch, tmp_path, media_cls):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(main, "NewsFetcher", _Fetcher)
    monkeypatch.setattr(main, "ScriptWriter", _Writer)
    monkeypatch.setattr(main, "CyberMediaGenerator", media_cls)
    return main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)


def test_render_error_none_on_success(monkeypatch, tmp_path):
    class M:
        def __init__(self, settings=None):
            pass

        def build_video(self, scenes, name, cve, sev, is_sample=False):
            p = tmp_path / "output" / name
            p.write_bytes(b"x")
            return str(p)

    m = _run(monkeypatch, tmp_path, M)
    assert m["render_error"] is None and m["output_video"]
    on_disk = json.loads((tmp_path / "output" / "m.json").read_text(encoding="utf-8"))
    assert on_disk["render_error"] is None


def test_render_error_missing_file(monkeypatch, tmp_path):
    class M:
        def __init__(self, settings=None):
            pass

        def build_video(self, *a, **k):
            return str(tmp_path / "output" / "ghost.mp4")

    m = _run(monkeypatch, tmp_path, M)
    assert m["output_video"] is None
    assert m["render_error"] == "video file was not produced"


def test_render_error_non_string_return(monkeypatch, tmp_path):
    class M:
        def __init__(self, settings=None):
            pass

        def build_video(self, *a, **k):
            return None

    assert _run(monkeypatch, tmp_path, M)["render_error"] == "video file was not produced"


def test_render_error_exception_has_type_only(monkeypatch, tmp_path):
    class M:
        def __init__(self, settings=None):
            pass

        def build_video(self, *a, **k):
            raise RuntimeError("secret-token-abc")

    m = _run(monkeypatch, tmp_path, M)
    assert m["output_video"] is None
    assert m["render_error"] == "video generation failed: RuntimeError"
    assert "secret" not in (tmp_path / "output" / "m.json").read_text(encoding="utf-8")


# ---------- __main__ exit codes ----------
def _run_as_main(monkeypatch, tmp_path, produce):
    import core.config_loader as cl
    from modules.content_pipeline import news_fetcher, script_writer

    class M:
        def __init__(self, settings=None):
            pass

        def build_video(self, scenes, name, *a, **k):
            if not produce:
                return None
            p = tmp_path / "output" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x")
            return str(p)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cl, "load_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(news_fetcher, "NewsFetcher", _Fetcher)
    monkeypatch.setattr(script_writer, "ScriptWriter", _Writer)
    monkeypatch.setattr(mg, "CyberMediaGenerator", M)
    runpy.run_path(str(ROOT / "main.py"), run_name="__main__")


def test_main_exits_1_when_no_video(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as ei:
        _run_as_main(monkeypatch, tmp_path, produce=False)
    assert ei.value.code == 1


def test_main_exits_0_on_success(monkeypatch, tmp_path):
    try:
        _run_as_main(monkeypatch, tmp_path, produce=True)
    except SystemExit as e:
        pytest.fail(f"unexpected exit {e.code}")
