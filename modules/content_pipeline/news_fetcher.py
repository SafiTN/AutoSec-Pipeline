import logging
import time
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json
import certifi
import ssl
from datetime import datetime, timedelta, timezone


logger = logging.getLogger("AutoSec.NewsFetcher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdFetchError(RuntimeError):
    """يُرفع عند فشل جلب بيانات NVD بعد استنفاد كل المحاولات ودون السماح بالبيانات الاحتياطية."""


FALLBACK_ADVISORIES: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2025-29927-SAMPLE",
        "published": "2025-03-22T00:00:00.000",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "summary": (
            "Authorization bypass vulnerability in middleware request handling allows attackers "
            "to bypass internal security checks if external headers are not stripped at the edge."
        ),
        "reference_url": "https://nvd.nist.gov/",
        "is_sample": True,
    },
    {
        "cve_id": "CVE-2025-24813-SAMPLE",
        "published": "2025-03-10T00:00:00.000",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "summary": (
            "Improper path normalization and partial PUT request handling under non-default "
            "configuration can expose sensitive files or allow remote code execution."
        ),
        "reference_url": "https://nvd.nist.gov/",
        "is_sample": True,
    },
]


class NewsFetcher:
    """جالب أحدث الثغرات الأمنية (CVEs) مع إعادة محاولة وآلية Fallback موثوقة."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {}
        nvd_cfg = self.settings.get("nvd", {})
        self.api_url: str = nvd_cfg.get("api_url", NVD_API_URL)
        self.timeout_sec: int = nvd_cfg.get("timeout_sec", 12)
        self.max_retries: int = nvd_cfg.get("max_retries", 2)
        self.allow_fallback: bool = nvd_cfg.get("allow_fallback", False)

    def _extract_cvss_info(self, cve_item: Dict[str, Any]) -> Dict[str, Any]:
        metrics = cve_item.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key)
            if entries and isinstance(entries, list):
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity") or "UNKNOWN"
                return {"cvss_score": score, "severity": str(severity).upper()}
        return {"cvss_score": 0.0, "severity": "UNKNOWN"}

    def _parse_nvd_response(self, raw_json: str, limit: int) -> List[Dict[str, Any]]:
        data = json.loads(raw_json)
        vulnerabilities = data.get("vulnerabilities", [])
        advisories: List[Dict[str, Any]] = []

        for item in vulnerabilities[:limit]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN-CVE")
            published = cve.get("published", "")

            descriptions = cve.get("descriptions", [])
            summary = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value", "").strip()
                    break
            if not summary and descriptions:
                summary = descriptions[0].get("value", "").strip()

            cvss_info = self._extract_cvss_info(cve)
            refs = cve.get("references", [])
            ref_url = refs[0].get("url", "https://nvd.nist.gov/") if refs else "https://nvd.nist.gov/"

            advisories.append(
                {
                    "cve_id": cve_id,
                    "published": published,
                    "severity": cvss_info["severity"],
                    "cvss_score": cvss_info["cvss_score"],
                    "summary": summary,
                    "reference_url": ref_url,
                    "is_sample": False,
                }
            )
        return advisories

    def fetch_latest_cves(self, limit: int = 3) -> List[Dict[str, Any]]:
        """جلب أحدث الثغرات من NVD API مع إعادة المحاولة والعودة للبيانات الاحتياطية عند الفشل."""
        now_utc = datetime.now(timezone.utc)
        start_utc = now_utc - timedelta(days=14)

        params = {
            "resultsPerPage": max(1, min(limit, 10)),
            "pubStartDate": start_utc.strftime("%Y-%m-%dT00:00:00.000Z"),
            "pubEndDate": now_utc.strftime("%Y-%m-%dT23:59:59.999Z"),
        }
        url = f"{self.api_url}?{urlencode(params)}"

        last_error: Optional[BaseException] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info("[NewsFetcher] Fetching CVEs (attempt %d/%d) from NVD...", attempt, self.max_retries)
                req = Request(url, headers={"User-Agent": "AutoSec-Pipeline/1.0"})
                context = ssl.create_default_context(cafile=certifi.where())
                with urlopen(req, timeout=self.timeout_sec, context=context) as resp:
                    if resp.status == 200:
                        body = resp.read().decode("utf-8")
                        parsed = self._parse_nvd_response(body, limit=limit)
                        if parsed:
                            logger.info("[NewsFetcher] Retrieved %d CVE advisories.", len(parsed))
                            return parsed
                        last_error = ValueError("NVD response parsed to zero advisories")
            except (URLError, TimeoutError, json.JSONDecodeError, Exception) as exc:
                last_error = exc
                logger.warning("[NewsFetcher] Attempt %d failed: %s", attempt, exc)
                if attempt < self.max_retries:
                    time.sleep(1.5 * attempt)

        if not self.allow_fallback:
            raise NvdFetchError(
                f"NVD unreachable after {self.max_retries} attempts; refusing to fabricate CVE data "
                f"(set nvd.allow_fallback=true to allow sample data). Last error: {last_error}"
            )

        logger.warning(
            "[NewsFetcher] NVD unreachable after %d attempts; nvd.allow_fallback=true, "
            "returning SAMPLE/non-real fallback advisories (is_sample=True). Last error: %s",
            self.max_retries,
            last_error,
        )
        return FALLBACK_ADVISORIES[:limit]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    fetcher = NewsFetcher()
    items = fetcher.fetch_latest_cves(limit=2)
    print(json.dumps(items, indent=2, ensure_ascii=False))