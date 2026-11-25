"""T12: NewsFetcher NVD payload parsing and request construction (offline, urlopen mocked)."""

import json
from urllib.parse import parse_qs, urlparse

import pytest

from modules.content_pipeline import news_fetcher as nf
from modules.content_pipeline.news_fetcher import NewsFetcher


def _cve(cve_id="CVE-2026-1000", descs=None, metrics=None, refs=None):
    item = {"id": cve_id, "published": "2026-01-02T03:04:05.000"}
    if descs is not None:
        item["descriptions"] = descs
    if metrics is not None:
        item["metrics"] = metrics
    if refs is not None:
        item["references"] = refs
    return {"cve": item}


def _metric(score, sev=None, top_level_sev=None):
    data = {"baseScore": score}
    if sev:
        data["baseSeverity"] = sev
    entry = {"cvssData": data}
    if top_level_sev:
        entry["baseSeverity"] = top_level_sev
    return [entry]


def _parse(vulns, limit=10):
    return NewsFetcher()._parse_nvd_response(json.dumps({"vulnerabilities": vulns}), limit)


def test_realistic_payload_parsed():
    out = _parse(
        [
            _cve(
                descs=[{"lang": "es", "value": "hola"}, {"lang": "en", "value": "  English text.  "}],
                metrics={"cvssMetricV31": _metric(9.8, "CRITICAL")},
                refs=[{"url": "https://vendor.example/adv"}],
            )
        ]
    )
    assert out == [
        {
            "cve_id": "CVE-2026-1000",
            "published": "2026-01-02T03:04:05.000",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "summary": "English text.",
            "reference_url": "https://vendor.example/adv",
            "is_sample": False,
        }
    ]


def test_cvss_preference_v40_over_v31_over_v30():
    f = NewsFetcher()
    both = {"cvssMetricV30": _metric(5.0, "MEDIUM"), "cvssMetricV31": _metric(7.0, "HIGH")}
    assert f._extract_cvss_info({"metrics": both})["cvss_score"] == 7.0
    allthree = dict(both, cvssMetricV40=_metric(9.0, "CRITICAL"))
    assert f._extract_cvss_info({"metrics": allthree})["cvss_score"] == 9.0
    assert f._extract_cvss_info({"metrics": {"cvssMetricV30": _metric(5.0, "medium")}}) == {
        "cvss_score": 5.0,
        "severity": "MEDIUM",
    }


def test_v2_only_and_missing_metrics_give_unknown_none():
    f = NewsFetcher()
    expected = {"cvss_score": None, "severity": "UNKNOWN"}
    assert f._extract_cvss_info({"metrics": {"cvssMetricV2": _metric(7.5)}}) == expected
    assert f._extract_cvss_info({"metrics": {}}) == expected
    assert f._extract_cvss_info({}) == expected
    assert f._extract_cvss_info({"metrics": {"cvssMetricV31": []}}) == expected


def test_severity_from_entry_level_and_casing():
    f = NewsFetcher()
    info = f._extract_cvss_info({"metrics": {"cvssMetricV31": _metric(6.1, None, "medium")}})
    assert info["severity"] == "MEDIUM"
    # score present but no severity anywhere -> UNKNOWN, score preserved
    info = f._extract_cvss_info({"metrics": {"cvssMetricV31": _metric(6.1)}})
    assert info == {"cvss_score": 6.1, "severity": "UNKNOWN"}


def test_description_falls_back_to_first_when_no_english():
    out = _parse([_cve(descs=[{"lang": "es", "value": " solo espanol "}])])
    assert out[0]["summary"] == "solo espanol"


def test_missing_descriptions_refs_and_id_use_safe_defaults():
    out = _parse([{"cve": {}}])
    assert out[0]["cve_id"] == "UNKNOWN-CVE"
    assert out[0]["summary"] == ""
    assert out[0]["reference_url"] == "https://nvd.nist.gov/"
    assert out[0]["severity"] == "UNKNOWN" and out[0]["cvss_score"] is None
    assert out[0]["is_sample"] is False


def test_limit_slices_results():
    vulns = [_cve(f"CVE-2026-{i}") for i in range(1000, 1005)]
    assert [a["cve_id"] for a in _parse(vulns, limit=2)] == ["CVE-2026-1000", "CVE-2026-1001"]
    assert _parse(vulns, limit=0) == []


def test_empty_vulnerabilities_and_missing_key():
    assert _parse([]) == []
    assert NewsFetcher()._parse_nvd_response("{}", 3) == []


def test_malformed_json_raises():
    with pytest.raises(json.JSONDecodeError):
        NewsFetcher()._parse_nvd_response("<html>502</html>", 3)


def test_very_long_summary_preserved_not_crashing():
    long = "A" * 50_000
    assert len(_parse([_cve(descs=[{"lang": "en", "value": long}])])[0]["summary"]) == 50_000


class _Resp:
    def __init__(self, body, status=200):
        self._b, self.status = body, status

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_request_params_headers_timeout(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None, context=None):
        seen.update(url=req.full_url, headers=dict(req.header_items()), timeout=timeout, ctx=context)
        return _Resp(json.dumps({"vulnerabilities": [_cve()]}).encode())

    monkeypatch.setattr(nf, "urlopen", fake_urlopen)
    fetcher = NewsFetcher(
        {"nvd": {"api_url": "https://example.invalid/x", "timeout_sec": 7, "max_results": 5, "lookback_days": 3}}
    )
    assert len(fetcher.fetch_latest_cves(limit=99)) == 1
    parsed = urlparse(seen["url"])
    q = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://example.invalid/x"
    assert q["resultsPerPage"] == ["5"]  # clamped to max_results
    assert q["pubStartDate"][0].endswith("T00:00:00.000Z")
    assert q["pubEndDate"][0].endswith("T23:59:59.999Z")
    assert seen["timeout"] == 7
    assert seen["headers"]["User-agent"].startswith("AutoSec-Pipeline")
    assert seen["ctx"] is not None


def test_results_per_page_never_below_one(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None, context=None):
        seen["url"] = req.full_url
        return _Resp(json.dumps({"vulnerabilities": [_cve()]}).encode())

    monkeypatch.setattr(nf, "urlopen", fake_urlopen)
    monkeypatch.setattr(nf.time, "sleep", lambda s: None)
    with pytest.raises(nf.NvdFetchError):  # limit=0 slices to zero advisories
        NewsFetcher().fetch_latest_cves(limit=0)
    assert parse_qs(urlparse(seen["url"]).query)["resultsPerPage"] == ["1"]


def test_non_200_and_timeout_exhaust_retries_without_fallback(monkeypatch):
    monkeypatch.setattr(nf.time, "sleep", lambda s: None)
    calls = []

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(1)
        if len(calls) == 1:
            return _Resp(b"{}", status=503)
        raise TimeoutError("timed out")

    monkeypatch.setattr(nf, "urlopen", fake_urlopen)
    with pytest.raises(nf.NvdFetchError):
        NewsFetcher({"nvd": {"max_retries": 2}}).fetch_latest_cves(limit=1)
    assert len(calls) == 2


def test_fallback_sliced_by_limit_and_marked_sample(monkeypatch):
    monkeypatch.setattr(nf.time, "sleep", lambda s: None)
    monkeypatch.setattr(nf, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    out = NewsFetcher({"nvd": {"max_retries": 1, "allow_fallback": True}}).fetch_latest_cves(limit=1)
    assert len(out) == 1 and out[0]["is_sample"] is True
