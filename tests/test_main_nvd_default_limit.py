"""
Test for T02 AC e: main.run_pipeline(cve_limit=None) must forward
nvd.default_limit (read from settings) to NewsFetcher.fetch_latest_cves as
the `limit=` kwarg, instead of hard-coding 3.

Fully offline: load_settings, NewsFetcher, ScriptWriter and CyberMediaGenerator
are all replaced with stubs/mocks so no real config file, NVD, Ollama or
Edge-TTS/MoviePy work happens. Follows the stub style already used in
tests/test_main_sample_fallback.py.
"""
from unittest.mock import MagicMock

from modules.content_pipeline.news_fetcher import FALLBACK_ADVISORIES

import main


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
    def __init__(self, settings=None):
        self.settings = settings

    def build_video(self, scenes, final_video_name="cyber_episode.mp4", cve_id=None, severity=None):
        return "/fake/output/episode.mp4"


def _fake_settings(default_limit: int):
    return {"nvd": {"default_limit": default_limit, "allow_fallback": False}}


def test_run_pipeline_uses_nvd_default_limit_when_cve_limit_is_none(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    custom_default_limit = 7
    monkeypatch.setattr(main, "load_settings", lambda: _fake_settings(custom_default_limit))

    mock_fetcher_instance = MagicMock()
    mock_fetcher_instance.fetch_latest_cves.return_value = [dict(FALLBACK_ADVISORIES[0])]
    mock_fetcher_cls = MagicMock(return_value=mock_fetcher_instance)
    monkeypatch.setattr(main, "NewsFetcher", mock_fetcher_cls)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)

    main.run_pipeline(run_harness=False, cve_limit=None, max_scenes=1)

    mock_fetcher_instance.fetch_latest_cves.assert_called_with(limit=custom_default_limit)


def test_run_pipeline_explicit_cve_limit_overrides_nvd_default_limit(monkeypatch, tmp_path):
    """An explicit cve_limit must win over nvd.default_limit (not be ignored)."""
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(main, "load_settings", lambda: _fake_settings(default_limit=9))

    mock_fetcher_instance = MagicMock()
    mock_fetcher_instance.fetch_latest_cves.return_value = [dict(FALLBACK_ADVISORIES[0])]
    mock_fetcher_cls = MagicMock(return_value=mock_fetcher_instance)
    monkeypatch.setattr(main, "NewsFetcher", mock_fetcher_cls)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGenerator)

    main.run_pipeline(run_harness=False, cve_limit=5, max_scenes=1)

    mock_fetcher_instance.fetch_latest_cves.assert_called_with(limit=5)
