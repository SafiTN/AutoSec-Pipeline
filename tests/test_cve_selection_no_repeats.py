"""
Tests for T05: better CVE selection (CVSS-presence filter + repeat-avoidance)
and the new `output/covered_cves.json` persistent state file.

Covers backlog item T05 AC point 8 (docs/BACKLOG.md) per
docs/adr/0001-covered-cves-state-file.md:
  - `_select_primary_advisory` CVSS-None filtering, covered-id filtering, the
    three distinct ValueError cases, and back-compat with no second argument.
  - `_load_covered_cve_ids` / `_record_covered_cve` persistence helpers
    (missing file, corrupt JSON, non-dict JSON, merge-on-write, ISO timestamp).
  - `run_pipeline`-level integration: a real advisory is recorded only after a
    fully successful run; a failed-media-generation run and a sample/fallback
    run must never be recorded.

Fully offline: NewsFetcher, ScriptWriter and CyberMediaGenerator are replaced
with lightweight stubs (style follows tests/test_main_sample_fallback.py and
tests/test_main_nvd_default_limit.py). Every settings dict used here that can
reach a successful run_pipeline completion sets `paths.output_dir` to an
absolute path inside `tmp_path` -- `core.config_loader.resolve_project_path`
resolves relative paths against the repo's PROJECT_ROOT, not the cwd, so a
relative `output_dir` would otherwise leak a stray `covered_cves.json` into
the real repository (see docs/adr/0001-covered-cves-state-file.md and the
pre-existing stubbing in tests/test_main_sample_fallback.py).
"""
import json
import logging
from datetime import datetime
from pathlib import Path

import pytest

import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _settings_for_tmp(tmp_path, nvd_overrides=None):
    """Settings dict whose covered_cves.json always resolves inside tmp_path."""
    nvd_cfg = {
        "api_url": "https://example.invalid/cves",
        "max_results": 10,
        "default_limit": 3,
        "allow_fallback": False,
    }
    nvd_cfg.update(nvd_overrides or {})
    return {
        "nvd": nvd_cfg,
        "paths": {
            "output_dir": str(tmp_path / "output"),
            "covered_cves_filename": "covered_cves.json",
        },
    }


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


class _StubMediaGeneratorSuccess:
    """Mirrors the real CyberMediaGenerator.build_video signature; always succeeds."""

    def __init__(self, settings=None):
        self.settings = settings

    def build_video(self, scenes, final_video_name="cyber_episode.mp4", cve_id=None,
                    severity=None, is_sample=False):
        out = Path(self.settings["paths"]["output_dir"]) / final_video_name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"fake-mp4")
        return str(out)


class _StubMediaGeneratorReturnsNone(_StubMediaGeneratorSuccess):
    """build_video "fails" by returning None (no file produced)."""

    def build_video(self, *args, **kwargs):
        return None


class _StubFetcherReal:
    """Returns a single real (non-sample) advisory with a known CVSS score."""

    def __init__(self, settings=None):
        self.settings = settings

    def fetch_latest_cves(self, limit=3):
        return [
            {
                "cve_id": "CVE-2026-77777",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "summary": "Example real advisory for test.",
                "reference_url": "https://nvd.nist.gov/",
                "is_sample": False,
            }
        ]


class _StubFetcherSample:
    def __init__(self, settings=None):
        self.settings = settings

    def fetch_latest_cves(self, limit=3):
        return [
            {
                "cve_id": "CVE-2025-99999-SAMPLE",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "summary": "Fallback sample advisory.",
                "reference_url": "https://nvd.nist.gov/",
                "is_sample": True,
            }
        ]


# ---------------------------------------------------------------------------
# AC 8b/8c/8d: _select_primary_advisory filtering + ValueError cases.
# ---------------------------------------------------------------------------

def test_select_primary_advisory_empty_list_raises_value_error():
    with pytest.raises(ValueError, match="No CVE advisories available"):
        main._select_primary_advisory([])


def test_select_primary_advisory_all_missing_cvss_raises_distinct_value_error():
    advisories = [
        {"cve_id": "CVE-A", "cvss_score": None},
        {"cve_id": "CVE-B", "cvss_score": None},
    ]
    with pytest.raises(ValueError, match="CVSS"):
        main._select_primary_advisory(advisories)


def test_select_primary_advisory_all_covered_raises_distinct_value_error():
    advisories = [
        {"cve_id": "CVE-A", "cvss_score": 5.0},
        {"cve_id": "CVE-B", "cvss_score": 9.1},
    ]
    covered = {"CVE-A", "CVE-B"}
    with pytest.raises(ValueError, match="covered"):
        main._select_primary_advisory(advisories, covered)


def test_select_primary_advisory_mix_of_no_cvss_and_covered_leaves_one_valid_candidate():
    advisories = [
        {"cve_id": "CVE-NOCVSS", "cvss_score": None},
        {"cve_id": "CVE-COVERED", "cvss_score": 5.0},
        {"cve_id": "CVE-VALID", "cvss_score": 7.0},
    ]
    covered = {"CVE-COVERED"}
    selected = main._select_primary_advisory(advisories, covered)
    assert selected["cve_id"] == "CVE-VALID"


def test_select_primary_advisory_drops_covered_and_picks_best_remaining():
    advisories = [
        {"cve_id": "CVE-A", "cvss_score": 9.5},
        {"cve_id": "CVE-B", "cvss_score": 7.0},
        {"cve_id": "CVE-C", "cvss_score": 6.0},
    ]
    covered = {"CVE-A"}
    selected = main._select_primary_advisory(advisories, covered)
    assert selected["cve_id"] == "CVE-B"


def test_select_primary_advisory_highest_cvss_wins_with_no_covered_arg_backcompat():
    advisories = [
        {"cve_id": "CVE-A", "cvss_score": 5.0},
        {"cve_id": "CVE-B", "cvss_score": 9.1},
        {"cve_id": "CVE-C", "cvss_score": 7.0},
    ]
    # No second argument at all -> must behave exactly like before T05.
    selected = main._select_primary_advisory(advisories)
    assert selected["cve_id"] == "CVE-B"


# ---------------------------------------------------------------------------
# AC 8e: _load_covered_cve_ids -- missing file, corrupt JSON, non-dict JSON.
# ---------------------------------------------------------------------------

def test_load_covered_cve_ids_missing_file_returns_empty_set(tmp_path):
    settings = _settings_for_tmp(tmp_path)
    assert main._load_covered_cve_ids(settings) == set()


def test_load_covered_cve_ids_valid_file_returns_keys_as_set(tmp_path):
    settings = _settings_for_tmp(tmp_path)
    path = main._covered_cves_path(settings)
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"CVE-X": "2026-01-01T00:00:00+00:00"}, f)

    assert main._load_covered_cve_ids(settings) == {"CVE-X"}


def test_load_covered_cve_ids_corrupt_json_returns_empty_set_and_warns(tmp_path, caplog):
    settings = _settings_for_tmp(tmp_path)
    path = main._covered_cves_path(settings)
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not valid json")

    with caplog.at_level(logging.WARNING, logger="AutoSec.Main"):
        result = main._load_covered_cve_ids(settings)

    assert result == set()
    assert any("not valid JSON" in rec.message for rec in caplog.records)


def test_load_covered_cve_ids_non_dict_json_returns_empty_set_and_warns(tmp_path, caplog):
    settings = _settings_for_tmp(tmp_path)
    path = main._covered_cves_path(settings)
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(["CVE-A", "CVE-B"], f)

    with caplog.at_level(logging.WARNING, logger="AutoSec.Main"):
        result = main._load_covered_cve_ids(settings)

    assert result == set()
    assert any("did not contain a JSON object" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# AC 8e/8f: _record_covered_cve -- create, merge, ISO timestamp format.
# ---------------------------------------------------------------------------

def test_record_covered_cve_creates_file_when_missing(tmp_path):
    settings = _settings_for_tmp(tmp_path)
    path = main._covered_cves_path(settings)
    assert not __import__("os").path.exists(path)

    main._record_covered_cve(settings, "CVE-2026-11111")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "CVE-2026-11111" in data


def test_record_covered_cve_merges_without_dropping_existing_entries(tmp_path):
    settings = _settings_for_tmp(tmp_path)
    path = main._covered_cves_path(settings)
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"CVE-OLD": "2025-01-01T00:00:00+00:00"}, f)

    main._record_covered_cve(settings, "CVE-NEW")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["CVE-OLD"] == "2025-01-01T00:00:00+00:00"
    assert "CVE-NEW" in data


def test_record_covered_cve_writes_valid_iso8601_utc_timestamp(tmp_path):
    settings = _settings_for_tmp(tmp_path)
    main._record_covered_cve(settings, "CVE-2026-22222")

    path = main._covered_cves_path(settings)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_ts = data["CVE-2026-22222"]
    # datetime.now(timezone.utc).isoformat() always keeps a UTC offset suffix
    # (e.g. "+00:00"); fromisoformat must parse it back without error.
    parsed = datetime.fromisoformat(raw_ts)
    assert parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


# ---------------------------------------------------------------------------
# AC 8f/8g: run_pipeline integration -- record only on full, real success.
# ---------------------------------------------------------------------------

def test_run_pipeline_success_with_real_advisory_records_covered_cve(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = _settings_for_tmp(tmp_path)
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherReal)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGeneratorSuccess)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["output_video"] is not None
    assert manifest["is_sample"] is False

    covered_path = main._covered_cves_path(settings)
    with open(covered_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "CVE-2026-77777" in data


def test_run_pipeline_media_generation_failure_does_not_record_cve(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = _settings_for_tmp(tmp_path)
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherReal)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    # The "failure" is simulated by build_video returning None (no file).
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGeneratorReturnsNone)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["output_video"] is None

    covered_path = main._covered_cves_path(settings)
    import os
    assert not os.path.exists(covered_path)


def test_run_pipeline_sample_advisory_never_recorded_even_on_full_success(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = _settings_for_tmp(tmp_path)
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "NewsFetcher", _StubFetcherSample)
    monkeypatch.setattr(main, "ScriptWriter", _StubScriptWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _StubMediaGeneratorSuccess)

    manifest = main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert manifest["output_video"] is not None
    assert manifest["is_sample"] is True

    covered_path = main._covered_cves_path(settings)
    import os
    assert not os.path.exists(covered_path)
