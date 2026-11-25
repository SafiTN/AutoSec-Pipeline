"""
Tests for T04: NewsFetcher must never fabricate CVE data silently.

All HTTP access is mocked (urlopen is monkeypatched); nothing here touches the
live NVD API, Ollama, or TTS. Covers backlog item T04 AC points 1-3 and 7,
plus the edge cases called out in the QA brief: empty NVD response,
HTTP/timeout errors, advisory without CVSS, and duplicate CVE ids.
"""

import json
from urllib.error import URLError

import pytest

from modules.content_pipeline.news_fetcher import (
    FALLBACK_ADVISORIES,
    NVD_API_URL,
    NewsFetcher,
    NvdFetchError,
)


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


def _settings(allow_fallback: bool, max_retries: int = 2, **extra_nvd):
    nvd_cfg = {
        "api_url": "https://example.invalid/cves",
        "timeout_sec": 1,
        "max_retries": max_retries,
        "allow_fallback": allow_fallback,
    }
    nvd_cfg.update(extra_nvd)
    return {"nvd": nvd_cfg}


def _no_sleep(monkeypatch):
    # Retries sleep 1.5s * attempt; patch it out so retry tests stay fast/deterministic.
    monkeypatch.setattr("modules.content_pipeline.news_fetcher.time.sleep", lambda *_a, **_k: None)


# ---------------------------------------------------------------------------
# AC 1 & 2: config comes from the `nvd` section, with safe defaults.
# ---------------------------------------------------------------------------


def test_init_reads_all_fields_from_nvd_section():
    fetcher = NewsFetcher(settings=_settings(allow_fallback=True, max_retries=5))
    assert fetcher.api_url == "https://example.invalid/cves"
    assert fetcher.timeout_sec == 1
    assert fetcher.max_retries == 5
    assert fetcher.allow_fallback is True


def test_init_defaults_are_safe_without_any_settings():
    fetcher = NewsFetcher()
    assert fetcher.api_url == NVD_API_URL
    assert fetcher.timeout_sec == 12
    assert fetcher.max_retries == 2
    assert fetcher.allow_fallback is False


def test_init_allow_fallback_defaults_false_when_key_missing():
    # `nvd` section present but without `allow_fallback` -> must still default to False.
    fetcher = NewsFetcher(settings={"nvd": {"max_retries": 1}})
    assert fetcher.allow_fallback is False


# ---------------------------------------------------------------------------
# AC 3: all retries exhausted.
# ---------------------------------------------------------------------------


def test_fetch_raises_nvd_fetch_error_when_allow_fallback_false(monkeypatch):
    """Network errors on every attempt + allow_fallback False -> NvdFetchError, no fallback data."""
    _no_sleep(monkeypatch)

    def _raise_urlopen(*_args, **_kwargs):
        raise URLError("network unreachable")

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _raise_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=2))

    with pytest.raises(NvdFetchError) as excinfo:
        fetcher.fetch_latest_cves(limit=3)

    assert "2" in str(excinfo.value)  # mentions attempt count


def test_fetch_raises_when_allow_fallback_unset_default(monkeypatch):
    _no_sleep(monkeypatch)

    def _raise_urlopen(*_args, **_kwargs):
        raise URLError("timeout")

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _raise_urlopen)

    fetcher = NewsFetcher(settings={"nvd": {"max_retries": 1}})
    assert fetcher.allow_fallback is False

    with pytest.raises(NvdFetchError):
        fetcher.fetch_latest_cves(limit=2)


def test_fetch_returns_tagged_fallback_when_allowed(monkeypatch):
    """Same failure scenario, but allow_fallback True -> tagged fallback list, respecting limit."""
    _no_sleep(monkeypatch)

    def _raise_urlopen(*_args, **_kwargs):
        raise URLError("boom")

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _raise_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=True, max_retries=2))

    result = fetcher.fetch_latest_cves(limit=1)

    assert len(result) == 1
    assert result == FALLBACK_ADVISORIES[:1]
    assert all(item.get("is_sample") is True for item in result)


def test_fetch_returns_full_fallback_list_when_limit_covers_it(monkeypatch):
    _no_sleep(monkeypatch)

    def _raise_urlopen(*_args, **_kwargs):
        raise URLError("boom")

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _raise_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=True, max_retries=1))

    result = fetcher.fetch_latest_cves(limit=10)

    assert len(result) == len(FALLBACK_ADVISORIES)
    assert all(item["is_sample"] is True for item in result)


# ---------------------------------------------------------------------------
# Edge cases: empty NVD response, HTTP error, malformed JSON -> all treated as
# failed attempts, exhausting retries exactly like network errors.
# ---------------------------------------------------------------------------


def test_fetch_empty_parsed_response_is_treated_as_failure(monkeypatch):
    empty_body = json.dumps({"vulnerabilities": []}).encode("utf-8")

    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(empty_body, status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=1))

    with pytest.raises(NvdFetchError):
        fetcher.fetch_latest_cves(limit=3)


def test_fetch_non_200_status_is_treated_as_failure(monkeypatch):
    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(b"{}", status=503)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=1))

    with pytest.raises(NvdFetchError):
        fetcher.fetch_latest_cves(limit=3)


def test_fetch_malformed_json_is_treated_as_failure(monkeypatch):
    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(b"{not valid json", status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=1))

    with pytest.raises(NvdFetchError):
        fetcher.fetch_latest_cves(limit=3)


# ---------------------------------------------------------------------------
# Successful parse path: real advisories are explicitly tagged is_sample=False.
# ---------------------------------------------------------------------------


def _nvd_body(entries):
    return json.dumps({"vulnerabilities": entries}).encode("utf-8")


def test_fetch_success_marks_real_advisories_not_sample(monkeypatch):
    body = _nvd_body(
        [
            {
                "cve": {
                    "id": "CVE-2026-10001",
                    "published": "2026-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A real vulnerability description."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]},
                    "references": [{"url": "https://example.com/advisory"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-10002",
                    "published": "2026-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Another real vulnerability."}],
                    "metrics": {},
                    "references": [],
                }
            },
        ]
    )

    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(body, status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=2))
    result = fetcher.fetch_latest_cves(limit=5)

    assert len(result) == 2
    assert all(item["is_sample"] is False for item in result)
    assert result[0]["cve_id"] == "CVE-2026-10001"
    assert result[0]["severity"] == "HIGH"
    assert result[0]["cvss_score"] == 8.8


def test_advisory_without_cvss_defaults_gracefully(monkeypatch):
    body = _nvd_body(
        [
            {
                "cve": {
                    "id": "CVE-2026-20000",
                    "published": "2026-02-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "No CVSS metrics published yet."}],
                    "metrics": {},
                    "references": [],
                }
            }
        ]
    )

    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(body, status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=1))
    result = fetcher.fetch_latest_cves(limit=3)

    assert len(result) == 1
    assert result[0]["cvss_score"] is None
    assert result[0]["severity"] == "UNKNOWN"
    assert result[0]["is_sample"] is False


def test_duplicate_cve_ids_are_both_returned_without_crashing(monkeypatch):
    """NewsFetcher itself does not dedupe (owned by T05); this just locks in current,
    non-crashing behavior so a future change to dedup logic is a deliberate decision."""
    dup_entry = {
        "cve": {
            "id": "CVE-2026-30000",
            "published": "2026-03-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Duplicate advisory entry."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}}]},
            "references": [],
        }
    }
    body = _nvd_body([dup_entry, dup_entry])

    def _fake_urlopen(_req, timeout=None, context=None):
        return _FakeResponse(body, status=200)

    monkeypatch.setattr("modules.content_pipeline.news_fetcher.urlopen", _fake_urlopen)

    fetcher = NewsFetcher(settings=_settings(allow_fallback=False, max_retries=1))
    result = fetcher.fetch_latest_cves(limit=5)

    assert len(result) == 2
    assert result[0]["cve_id"] == result[1]["cve_id"] == "CVE-2026-30000"
