"""Pure fact-check validator for generated episode scripts (ADR 0002).

No I/O and no logging of scene text. Every regex is linear (bounded gaps, no
nested quantifiers) so long LLM output cannot trigger catastrophic backtracking.
"""

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

SCENE_FIELDS = ("title", "narration", "visual_cue")
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "none")

_CVE_RE = re.compile(r"cve-\d{4}-\d{4,}")
_LEVEL = "(" + "|".join(SEVERITY_LEVELS) + ")"
_SEVERITY_RES = (
    re.compile(rf"(?<!\w){_LEVEL}[\s-]{{0,5}}severity(?!\w)"),
    re.compile(rf"(?<!\w)severity(?:\s{{1,5}}level)?\s{{0,5}}(?:of|is|:)\s{{0,5}}{_LEVEL}(?!\w)"),
    re.compile(rf"(?<!\w)rated(?:\s{{0,5}}:\s{{0,5}}|\s{{1,5}}){_LEVEL}(?!\w)"),
)
_CVSS_VERSION_RE = re.compile(
    r"(?<=cvss)(?:\s{0,3}(?:v|version\s)\s{0,2}\d+(?:\.\d+)?|\s{0,3}(?:3\.\d|4\.0)(?![\d.]*\d))"
)
_CVSS_RE = re.compile(r"cvss[^\d]{0,20}(\d+\.\d+)")
_VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)*)(?!\w|\.\d)")


class ScriptValidationError(ValueError):
    """Raised when no script attempt passes fact-checking. Never carries scene text."""

    def __init__(self, violations: List[str], attempts: int):
        self.violations = list(violations)
        self.attempts = attempts
        shown = "; ".join(self.violations) if self.violations else "no valid script produced"
        super().__init__(f"Script failed fact-check after {attempts} attempt(s): {shown}")


def _normalize(text: Any) -> str:
    value = unicodedata.normalize("NFKC", str(text)).casefold()
    value = "".join(c for c in value if unicodedata.category(c) != "Cf")
    return re.sub(r"\s+", " ", value).strip()


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _advisory_text(advisory: Mapping[str, Any]) -> str:
    parts = [advisory.get(k) for k in ("summary", "affected_versions", "fixed_versions")]
    return _normalize(" ".join(_flatten(p) for p in parts))


def _term_regex(term: str) -> Optional[Tuple[str, "re.Pattern[str]"]]:
    norm = _normalize(term)
    if not norm:
        return None
    if norm.endswith("iz"):
        return norm, re.compile(r"(?<!\w)" + re.escape(norm))
    return norm, re.compile(r"(?<!\w)" + re.escape(norm) + r"(?!\w)")


def _cvss_equal(token: str, score: Any) -> bool:
    try:
        return float(token) == float(score)
    except (TypeError, ValueError):
        return False


def _check_text(text: str, advisory: Mapping[str, Any], adv_text: str, text_rules: bool,
                terms: List[Tuple[str, "re.Pattern[str]"]], out: List[str]) -> None:
    # (a) CVE ids
    adv_cve_norm = _normalize(advisory.get("cve_id", ""))
    adv_match = _CVE_RE.search(adv_cve_norm)
    adv_cve = adv_match.group(0) if adv_match else adv_cve_norm
    for token in _CVE_RE.findall(text):
        if token != adv_cve:
            out.append(f"CVE id {token.upper()} does not match advisory")

    # (b) severity claims
    adv_sev = _normalize(advisory.get("severity", ""))
    for rx in _SEVERITY_RES:
        for level in rx.findall(text):
            if adv_sev not in SEVERITY_LEVELS:
                out.append(f"severity claim {level.upper()} made but advisory severity is not specified")
            elif level != adv_sev:
                out.append(f"severity {level.upper()} does not match advisory")

    # (c) CVSS score
    score = advisory.get("cvss_score")
    text = _CVSS_VERSION_RE.sub("", text)  # drop metric version ("CVSS v3.1")
    for token in _CVSS_RE.findall(text):
        if not _cvss_equal(token, score):
            out.append(f"CVSS score {token} does not match advisory")

    if not text_rules:
        return

    # (d) invented versions
    adv_versions = set(_VERSION_RE.findall(adv_text))
    for token in _VERSION_RE.findall(text):
        if token in adv_versions or _cvss_equal(token, score):
            continue
        out.append(f"version {token} not present in advisory data")

    # (e) forbidden terms
    for term, rx in terms:
        if rx.search(text):
            out.append(f"forbidden term: {term}")


def validate_script(
    scenes: Iterable[Mapping[str, Any]],
    advisory: Mapping[str, Any],
    rules: Optional[Mapping[str, Any]],
    *,
    skip_text_rules: bool = False,
) -> List[str]:
    """Return human-readable violations (empty list = pass).

    `skip_text_rules=True` applies only rules (a)-(c); used for the deterministic fallback.
    """
    rules = rules or {}
    terms = [t for t in (_term_regex(x) for x in rules.get("forbidden_terms", []) or []) if t]
    adv_text = _advisory_text(advisory)
    violations: List[str] = []
    for scene in scenes:
        for field in SCENE_FIELDS:
            text = _normalize(scene.get(field, "") if isinstance(scene, Mapping) else "")
            if text:
                _check_text(text, advisory, adv_text, not skip_text_rules, terms, violations)
    return list(dict.fromkeys(violations))
