"""
Tests for T04: main.py must not fabricate a default advisory, must let
NvdFetchError propagate out of run_pipeline, and must mark sample/fallback
output clearly in the manifest.

Fully offline: NewsFetcher, ScriptWriter and CyberMediaGenerator are replaced
with lightweight stubs so no real NVD/Ollama/Edge-TTS/MoviePy work happens.
"""
import json
from pathlib import Path

import pytest

import main
from modules.content_pipeline.news_fetcher import FALLBACK_ADVISORIES, NvdFetchError


# ---------------------------------------------------------------------------
# Stubs standing in for the real pipeline collaborators.
# ---------------------------------------------------------------------------

class _StubFetcherRaising:
    def __init__(self, settings=None):
        self.settings = settings

    def fetch_latest_cves(self, limit=3):
        raise NvdFetchError("simulated NVD outage (test stub)")


class _StubFetcherSample:
    """Mimics allow_fallback=True behavior: returns is_sample=True advisories."""

    def __init__(self, settings=None):
        self.settings = settings

    def fetch_latest_cves(self, limit=3):
        return [dict(FALLBACK_ADVISORIES[0])]


class _StubFetcherReal:
    def __init__(self, settings=None):
        self.settings = settings

    def fetch_latest_cves(self, limit=3):
        return [
            {
                "cve_id": "CVE-2026-55555",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "summary": "Example real advisory for test.",
                "reference_url": "https://nvd.nist.gov/",
                "is_sample": False,
            }
        ]


class _StubScriptWriter:
    def __init__(self, settings=None):
        self.settings = settings

    def generate_episode_script(self, advisory, max_scenes=3):
        return {
            "language": "en",
            "cve_id": advisory.get("cve_id"),
            "episode_title": "Example Episode Title",
            "scenes": [
                {"title": "Scene 1", "narration": "Some narration.", "visual_cue": "Some cue"},
            ],
        }


class _StubMediaGenerator:
    """Mirrors the real CyberMediaGenerator.build_video signature (no network/TTS)."""

    last_call_kwargs = None

    def __init__(self, settings=None):
        self.settings = settings

    def build_video(self, scenes, final_video_name="cyber_episode.mp4", cve_id=None,
                    severity=None, is_sample=False):
        _StubMediaGenerator.last_call_kwargs = {
            "scenes": scenes,
            "final_video_name": final_video_name,
            "cve_id": cve_id,
            "severity": severity,
            "is_sample": is_sample,
        }
        out = Path(self.settings["paths"]["output_dir"]) / final_video_name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"fake-mp4")
        return str(out)


@pytest.fixture(autouse=True)
def _tmp_settings(monkeypatch, tmp_path):
    """Route every output (manifest, covered_cves, video) into tmp_path."""
    settings = {
        "nvd": {"max_results": 10, "allow_fallback": False},
        "paths": {
            "output_dir": str(tmp_path / "output"),
            "default_video_filename": "cyber_episode.mp4",
            "manifest_filename": "last_episode_manifest.json",
            "covered_cves_filename": "covered_cves.json",
        },
    }
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    _StubMediaGenerator.last_call_kwargs = None
    return settings


# ---------------------------------------------------------------------------
# AC: _select_primary_advisory no longer fabricates CVE-ADVISORY-DEFAULT.
# ---------------------------------------------------------------------------

def test_select_primary_advisory_raises_on_empty_list():
    with pytest.raises(ValueError):
        main._select_primary_advisory([])


def test_select_primary_advisory_still_picks_highest_cvss():
    advisories = [
        {"cve_id": "CVE-A", "cvss_score": 5.0},
        {"cve_id": "CVE-B", "cvss_score": 9.1},
        {"cve_id": "CVE-C", "cvss_score": 7.0},
    ]
    selected = main._select_primary_advisory(advisories)
    assert selected["cve_id"] == "CVE-B"


# ---------------------------------------------------------------------------
# AC: run_pipeline must not swallow NvdFetchError.
# ---------------------------------------------------------------------------

def test_run_pipeline_propagates_nvd_fetch_error(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherRaising)

    with pytest.raises(NvdFetchError):
        main.run_pipeline(run_harness=False, cve_limit=3, max_scenes=3)

    # Pipeline must abort before ever touching the manifest/output directory.
    assert not (tmp_path / "output" / "last_episode_manifest.json").exists()


# ---------------------------------------------------------------------------
# AC: manifest carries is_sample, and the title is prefixed for sample data.
# ---------------------------------------------------------------------------

def test_run_pipeline_manifest_is_sample_true_for_fallback_advisory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherSample)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["is_sample"] is True
    assert manifest["selected_cve"]["is_sample"] is True

    manifest_path = tmp_path / "output" / "last_episode_manifest.json"
    assert manifest_path.exists()
    on_disk = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert on_disk["is_sample"] is True


def test_run_pipeline_manifest_is_sample_false_for_real_advisory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherReal)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)
    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["is_sample"] is False
    assert manifest["selected_cve"]["is_sample"] is False
    assert not manifest["episode_script"]["episode_title"].startswith("[SAMPLE]")


def test_run_pipeline_manifest_episode_title_is_prefixed_for_sample_per_ac(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherSample)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["episode_script"]["episode_title"].startswith("[SAMPLE] ")


# ---------------------------------------------------------------------------
# T09: path helpers, prompt_version, is_sample forwarding, media failure paths.
# ---------------------------------------------------------------------------

def test_manifest_path_comes_from_settings(tmp_path):
    settings = {"paths": {"output_dir": str(tmp_path / "o"), "manifest_filename": "m.json"}}
    assert Path(main._manifest_path(settings)) == tmp_path / "o" / "m.json"


def test_manifest_path_defaults_when_keys_missing():
    p = Path(main._manifest_path({}))
    assert p.name == "last_episode_manifest.json" and p.parent.name == "output"


def test_video_filename_from_settings_and_sample_prefix():
    s = {"paths": {"default_video_filename": "ep.mp4"}}
    assert main._video_filename(s, False) == "ep.mp4"
    assert main._video_filename(s, True) == "sample_ep.mp4"
    assert main._video_filename({}, True) == "sample_cyber_episode.mp4"


def _run(monkeypatch, fetcher, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", fetcher)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)
    return main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)


def test_build_video_gets_is_sample_true_for_sample_run(monkeypatch, tmp_path):
    manifest = _run(monkeypatch, _StubFetcherSample, tmp_path)
    kw = _StubMediaGenerator.last_call_kwargs
    assert kw["is_sample"] is True
    assert kw["final_video_name"] == "sample_cyber_episode.mp4"
    assert Path(manifest["output_video"]).name == "sample_cyber_episode.mp4"


def test_build_video_gets_is_sample_false_for_real_run(monkeypatch, tmp_path):
    manifest = _run(monkeypatch, _StubFetcherReal, tmp_path)
    kw = _StubMediaGenerator.last_call_kwargs
    assert kw["is_sample"] is False
    assert kw["final_video_name"] == "cyber_episode.mp4"
    assert Path(manifest["output_video"]).is_file()


def test_manifest_prompt_version_present(monkeypatch, tmp_path):
    class _Writer(_StubScriptWriter):
        def generate_episode_script(self, advisory, max_scenes=3):
            d = super().generate_episode_script(advisory, max_scenes)
            d["prompt_version"] = "v2"
            return d

    monkeypatch.setattr(main, "ScriptWriter", _Writer)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherSample)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)
    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)
    assert manifest["prompt_version"] == "v2"
    on_disk = json.loads((tmp_path / "output" / "last_episode_manifest.json").read_text("utf-8"))
    assert on_disk["prompt_version"] == "v2"


def test_manifest_prompt_version_none_when_absent(monkeypatch, tmp_path):
    manifest = _run(monkeypatch, _StubFetcherSample, tmp_path)
    assert "prompt_version" in manifest and manifest["prompt_version"] is None


class _MissingFileMedia(_StubMediaGenerator):
    def build_video(self, *a, **k):
        return str(Path(self.settings["paths"]["output_dir"]) / "ghost.mp4")


class _RaisingMedia(_StubMediaGenerator):
    def build_video(self, *a, **k):
        raise RuntimeError("tts exploded")


@pytest.mark.parametrize("media_cls", [_MissingFileMedia, _RaisingMedia])
def test_media_failure_writes_manifest_without_video_and_skips_recording(
    monkeypatch, tmp_path, media_cls
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherReal)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", media_cls)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["output_video"] is None
    on_disk = json.loads((tmp_path / "output" / "last_episode_manifest.json").read_text("utf-8"))
    assert on_disk["output_video"] is None
    assert not (tmp_path / "output" / "covered_cves.json").exists()
