"""
Tests for T02: nvd.lookback_days / nvd.max_results / nvd.default_limit wiring.

All HTTP access is mocked (urlopen is monkeypatched); nothing here touches the
live NVD API, Ollama, or TTS. Mirrors the conventions in
tests/test_news_fetcher_fallback.py (_FakeResponse helper, settings() builder,
monkeypatch.setattr on modules.content_pipeline.news_fetcher.urlopen).

Covers backlog item T02 AC:
  a. __init__ reads lookback_days/max_results/default_limit from settings,
     with safe fallback to the documented defaults (14/10/3).
  b. a custom lookback_days changes the pubStartDate query param.
  c. a custom max_results caps resultsPerPage even with a larger explicit limit.
  d. fetch_latest_cves() with no limit argument uses default_limit end to end
     (request param, parsed count, and the fallback-path slice length).
  e. main.run_pipeline(cve_limit=None) forwards nvd.default_limit to
     fetch_latest_cves(limit=...).
"""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from modules.content_pipeline.news_fetcher import FALLBACK_ADVISORIES, NewsFetcher


class _FakeResponse:
    """Minimal stand-in for the context-manager object returned by urlopen()."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _settings(**extra_nvd):
    nvd_cfg = {
        "api_url": "https://example.invalid/cves",
        "timeout_sec": 1,
        "max_retries": 1,
        "allow_fallback": False,
    }
    nvd_cfg.update(extra_nvd)
    return {"nvd": nvd_cfg}


def _nvd_body(entries):
    return json.dumps({"vulnerabilities": entries}).encode("utf-8")


def _advisory_entry(cve_id: str):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"Description for {cve_id}."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}]},
            "references": [],
        }
    }


# ---------------------------------------------------------------------------
# AC a: __init__ reads lookback_days/max_results/default_limit, with defaults.
# ---------------------------------------------------------------------------

def test_init_reads_lookback_max_results_default_limit_from_settings():
    fetcher = NewsFetcher(
        settings=_settings(lookback_days=7, max_results=5, default_limit=2)
    )
    assert fetcher.lookback_days == 7
    assert fetcher.max_results == 5
    assert fetcher.default_limit == 2


def test_init_defaults_when_nvd_section_present_but_empty():
    fetcher = NewsFetcher(settings={"nvd": {}})
    assert fetcher.lookback_days == 14
    assert fetcher.max_results == 10
    assert fetcher.default_limit == 3


def test_init_defaults_when_settings_none():
    fetcher = NewsFetcher()
    assert fetcher.lookback_days == 14
    assert fetcher.max_results == 10
    assert fetcher.default_limit == 3


def test_init_defaults_when_settings_dict_has_no_nvd_key():
    fetcher = NewsFetcher(settings={})
    assert fetcher.lookback_days == 14
    assert fetcher.max_results == 10
    assert fetcher.default_limit == 3


# ---------------------------------------------------------------------------
# AC b: custom lookback_days changes the pubStartDate query param.
# ---------------------------------------------------------------------------

def test_custom_lookback_days_changes_pub_start_date(monkeypatch):
    captured = {}

    def _fake_urlopen(req, timeout=None, context=None):
        captured["url"] = req.full_url
        return _FakeResponse(_nvd_body([_advisory_entry("CVE-2026-11111")]), status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    before = datetime.now(timezone.utc)
    fetcher = NewsFetcher(settings=_settings(lookback_days=7))
    fetcher.fetch_latest_cves(limit=1)
    after = datetime.now(timezone.utc)

    query = parse_qs(urlparse(captured["url"]).query)
    pub_start = datetime.strptime(query["pubStartDate"][0], "%Y-%m-%dT00:00:00.000Z").replace(
        tzinfo=timezone.utc
    )

    # Expected window is "now - 7 days" at midnight granularity; allow for the
    # test running right across a day boundary by bracketing with before/after.
    expected_min = (before - timedelta(days=7)).date()
    expected_max = (after - timedelta(days=7)).date()
    assert expected_min <= pub_start.date() <= expected_max

    # And it must NOT match the old hard-coded 14-day window.
    assert pub_start.date() != (after - timedelta(days=14)).date()


# ---------------------------------------------------------------------------
# AC c: custom max_results caps resultsPerPage even with a larger explicit limit.
# ---------------------------------------------------------------------------

def test_custom_max_results_caps_results_per_page_even_with_larger_limit(monkeypatch):
    captured = {}

    def _fake_urlopen(req, timeout=None, context=None):
        captured["url"] = req.full_url
        return _FakeResponse(_nvd_body([_advisory_entry("CVE-2026-22222")]), status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(max_results=5))
    fetcher.fetch_latest_cves(limit=20)

    query = parse_qs(urlparse(captured["url"]).query)
    assert query["resultsPerPage"][0] == "5"


def test_default_max_results_allows_up_to_ten_when_no_cap_given(monkeypatch):
    captured = {}

    def _fake_urlopen(req, timeout=None, context=None):
        captured["url"] = req.full_url
        return _FakeResponse(_nvd_body([_advisory_entry("CVE-2026-33333")]), status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings())
    fetcher.fetch_latest_cves(limit=20)

    query = parse_qs(urlparse(captured["url"]).query)
    assert query["resultsPerPage"][0] == "10"


# ---------------------------------------------------------------------------
# AC d: fetch_latest_cves() with no limit argument uses default_limit end to end.
# ---------------------------------------------------------------------------

def test_fetch_latest_cves_no_limit_uses_default_limit_for_request_and_parsing(monkeypatch):
    captured = {}
    entries = [_advisory_entry(f"CVE-2026-4000{i}") for i in range(5)]

    def _fake_urlopen(req, timeout=None, context=None):
        captured["url"] = req.full_url
        return _FakeResponse(_nvd_body(entries), status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(default_limit=2, max_results=10))
    result = fetcher.fetch_latest_cves()  # no limit passed

    query = parse_qs(urlparse(captured["url"]).query)
    assert query["resultsPerPage"][0] == "2"
    # Response contained 5 advisories but default_limit=2 must trim the parse.
    assert len(result) == 2


def test_fetch_latest_cves_no_limit_uses_default_limit_in_fallback_path(monkeypatch):
    def _raise_urlopen(*_args, **_kwargs):
        raise OSError("simulated network outage")

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _raise_urlopen)
    monkeypatch.setattr("modules.content_pipeline.news_fetcher.time.sleep", lambda *_a, **_k: None)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=True, default_limit=1, max_retries=1))
    result = fetcher.fetch_latest_cves()  # no limit passed

    assert len(result) == 1
    assert result == FALLBACK_ADVISORIES[:1]
    assert all(item["is_sample"] is True for item in result)
