"""
Tests for T04: main.py must not fabricate a default advisory, must let
NvdFetchError propagate out of run_pipeline, and must mark sample/fallback
output clearly in the manifest.

Fully offline: NewsFetcher, ScriptWriter and CyberMediaGenerator are replaced
with lightweight stubs so no real NVD/Ollama/Edge-TTS/MoviePy work happens.
"""
import json

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

    def build_video(self, scenes, final_video_name="cyber_episode.mp4", cve_id=None, severity=None):
        _StubMediaGenerator.last_call_kwargs = {
            "scenes": scenes,
            "final_video_name": final_video_name,
            "cve_id": cve_id,
            "severity": severity,
        }
        return "/fake/output/episode.mp4"


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
    # This test exercises manifest.is_sample only; it does not use load_settings
    # overrides, so covered_cves.json would otherwise be resolved (via
    # resolve_project_path, which is intentionally PROJECT_ROOT-based per
    # docs/adr/0001-covered-cves-state-file.md, not cwd-based) against the real
    # repo's output/ dir. Stub the T05 recording step out here so this
    # unrelated test can't leave a stray test CVE id in the real
    # output/covered_cves.json state file.
    monkeypatch.setattr(main, "_record_covered_cve", lambda *args, **kwargs: None)

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
