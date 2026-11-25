import json
import logging
import os
import re
import sys
import unicodedata
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from core.agent_runner import AgentRunner
from core.config_loader import DEFAULT_SETTINGS, load_settings
from core.prompt_optimizer import PROMPT_VERSION, PromptOptimizer
from modules.content_pipeline.script_validator import ScriptValidationError, validate_script

logger = logging.getLogger("AutoSec.ScriptWriter")


def _truncate(text: str, limit: int) -> str:
    """Cut at a word boundary when possible; never exceeds `limit` characters."""
    if len(text) <= limit:
        return text
    cut = text[:limit].rstrip()
    if " " in cut and text[limit] != " ":
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:-")


def _strip_cf(text: str) -> str:
    """Drop format chars (zero-width, bidi overrides) so stored text equals validated text."""
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def _first_sentence(text: str) -> str:
    match = re.match(r"\s*(.+?[.!?])(?:\s|$)", text, flags=re.DOTALL)
    return match.group(1) if match else text


def normalize_scenes(
    raw_scenes: Any,
    max_scenes: int,
    optimizer: PromptOptimizer,
) -> List[Dict[str, Any]]:
    """Pure, never-raising normalization of model scenes into the v2 schema.

    Scenes without usable narration are dropped. Missing `key_takeaway` is derived from
    the narration; missing/invalid `on_screen_bullets` become []. Legacy 3-key scenes pass.
    """
    scenes: List[Dict[str, Any]] = []
    if not isinstance(raw_scenes, list):
        return scenes
    def clean(t: str) -> str:
        return optimizer.clean_text(_strip_cf(t))

    def tts(t: str) -> str:
        return optimizer.sanitize_for_tts_hints(_strip_cf(t))

    for idx, sc in enumerate(raw_scenes[: max(0, int(max_scenes))], start=1):
        if not isinstance(sc, dict) or not isinstance(sc.get("narration"), str):
            continue
        narration = tts(sc["narration"])
        if not narration:
            continue

        def text(key: str, default: str) -> str:
            value = sc.get(key)
            return clean(value) if isinstance(value, str) and clean(value) else default

        takeaway = tts(sc["key_takeaway"]) if isinstance(sc.get("key_takeaway"), str) else ""
        takeaway = _truncate(takeaway or _first_sentence(narration), optimizer.max_takeaway_chars)

        raw_bullets = sc.get("on_screen_bullets")
        if isinstance(raw_bullets, str):
            raw_bullets = [raw_bullets]
        bullets: List[str] = []
        for item in raw_bullets if isinstance(raw_bullets, list) else []:
            if not isinstance(item, str):
                continue
            words = tts(item).split()
            bullet = _truncate(" ".join(words[:8]), optimizer.max_bullet_chars)
            if bullet:
                bullets.append(bullet)
            if len(bullets) >= optimizer.max_bullets:
                break

        scenes.append(
            {
                "title": text("title", f"Scene {idx}"),
                "narration": narration,
                "key_takeaway": takeaway,
                "on_screen_bullets": bullets,
                "visual_cue": text("visual_cue", "Technical security slide"),
            }
        )
    return scenes


class ScriptWriter:
    """مولد سيناريوهات الفيديو التقنية باللغة الإنجليزية انطلاقاً من بيانات الثغرات الأمنية."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        self.agent = AgentRunner(settings=self.settings)
        self.optimizer = PromptOptimizer(settings=self.settings)
        rules = dict(self.settings.get("script_validation", {}) or {})
        self.validation_rules: Dict[str, Any] = rules
        self.validation_enabled: bool = self._parse_enabled(rules.get("enabled", True))
        self.max_retries: int = self._parse_max_retries(rules.get("max_retries", 0))

    @staticmethod
    def _parse_enabled(value: Any) -> bool:
        """Fail-safe: only a real boolean False disables; odd values keep checking on."""
        if isinstance(value, bool):
            return value
        logger.warning("script_validation.enabled is not a boolean; keeping fact-check ENABLED")
        return True

    @staticmethod
    def _parse_max_retries(value: Any) -> int:
        try:
            return max(0, int(value))
        except (ValueError, TypeError):
            default = DEFAULT_SETTINGS["script_validation"]["max_retries"]
            logger.warning("script_validation.max_retries is not an integer; using default %d", default)
            return default

    @staticmethod
    def _extract_json_payload(raw_text: str) -> Optional[Dict[str, Any]]:
        if not raw_text:
            return None
        cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw_text, flags=re.IGNORECASE).strip()
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and isinstance(parsed.get("scenes"), list):
                return parsed
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                    if isinstance(parsed, dict) and isinstance(parsed.get("scenes"), list):
                        return parsed
                except json.JSONDecodeError:
                    return None
        return None

    def _build_fallback_scenes(self, advisory: Dict[str, Any]) -> List[Dict[str, str]]:
        cve_id = self.optimizer.sanitize_for_tts_hints(str(advisory.get("cve_id", "CVE-Advisory")))
        severity = str(advisory.get("severity", "HIGH")).upper()
        score = advisory.get("cvss_score", "N/A")
        summary = self.optimizer.sanitize_for_tts_hints(
            str(advisory.get("summary", "A security vulnerability was reported in software components."))
        )
        short_summary = summary[:280].rstrip(".")

        return [
            {
                "title": f"{cve_id} Overview",
                "narration": (
                    f"Security advisory {cve_id} is rated {severity} with a CVSS score of {score}. "
                    f"Understanding how this flaw behaves helps teams prioritize patching and exposure checks."
                ),
                "key_takeaway": "Check whether your systems are affected and plan a patch.",
                "on_screen_bullets": [cve_id, f"Severity {severity}", f"CVSS {score}"],
                "visual_cue": f"Title card showing {cve_id} and CVSS {score} ({severity})",
            },
            {
                "title": "Technical Impact & Root Cause",
                "narration": (
                    f"At a technical level, {short_summary}. "
                    f"Weaknesses like this often involve unvalidated inputs, trust boundaries, or misconfigured routing."
                ),
                "key_takeaway": "Weak input validation and trust boundaries are common root causes.",
                "on_screen_bullets": ["What the flaw is", "Who may be affected", "Why it matters"],
                "visual_cue": "Architecture diagram highlighting trust boundary and request flow",
            },
            {
                "title": "Defensive Mitigation & Hardening",
                "narration": (
                    "To defend against this class of vulnerability, apply official vendor patches promptly and enforce strict input validation. "
                    "Always verify security controls in an isolated test environment before rolling changes into production."
                ),
                "key_takeaway": "Patch promptly, then verify. Fixed version is not yet specified here.",
                "on_screen_bullets": ["Apply vendor patch", "Limit exposure", "Verify in test first"],
                "visual_cue": "Checklist of patch verification, least privilege, and regression testing",
            },
        ]

    def _attempt(
        self,
        prompts: Dict[str, str],
        feedback: Optional[str],
        max_scenes: int,
    ) -> Optional[List[Dict[str, str]]]:
        """One Ollama call: query, parse and sanitize. Returns None when nothing usable was parsed."""
        user_prompt = prompts["user_prompt"]
        if feedback:
            user_prompt = f"{user_prompt}\n\n{feedback}"
        raw_response = self.agent.query_local_agent(
            prompt=user_prompt,
            system_prompt=prompts["system_prompt"],
        )
        parsed = self._extract_json_payload(raw_response)
        scenes = normalize_scenes(parsed["scenes"], max_scenes, self.optimizer) if parsed else []
        return scenes or None

    @staticmethod
    def _validation_view(scenes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scenes plus extra pseudo-scenes carrying takeaway/bullet text, so the T06
        validator checks them with the same rules (validator itself is unchanged)."""
        view: List[Dict[str, Any]] = list(scenes)
        for sc in scenes:
            extras = [sc.get("key_takeaway", "")] + list(sc.get("on_screen_bullets") or [])
            view.extend({"narration": e} for e in extras if isinstance(e, str) and e)
            joined = " ".join(e for e in extras if isinstance(e, str) and e)
            if joined:
                view.append({"narration": joined})
        return view

    def _validate(
        self, scenes: List[Dict[str, Any]], advisory: Dict[str, Any], skip_text_rules: bool = False
    ) -> List[str]:
        return validate_script(
            self._validation_view(scenes), advisory, self.validation_rules, skip_text_rules=skip_text_rules
        )

    def _generate_validated(
        self,
        advisory: Dict[str, Any],
        prompts: Dict[str, str],
        max_scenes: int,
        cve_id: str,
    ) -> List[Dict[str, str]]:
        total = 1 + self.max_retries
        feedback: Optional[str] = None
        last_violations: List[str] = []
        parsed_any = False
        for attempt in range(1, total + 1):
            scenes = self._attempt(prompts, feedback, max_scenes)
            if scenes is None:
                logger.warning("[ScriptWriter] Attempt %d/%d for %s was unparseable.", attempt, total, cve_id)
                continue
            parsed_any = True
            violations = self._validate(scenes, advisory)
            if not violations:
                return scenes
            last_violations = violations
            logger.warning(
                "[ScriptWriter] Attempt %d/%d for %s failed fact-check (%d violation(s): %s).",
                attempt,
                total,
                cve_id,
                len(violations),
                ", ".join(sorted({v.split(" ")[0] for v in violations})),
            )
            feedback = self.optimizer.build_retry_feedback(violations)

        if parsed_any:
            raise ScriptValidationError(last_violations, total)

        logger.warning("[ScriptWriter] All attempts unparseable; using deterministic fallback for %s.", cve_id)
        fallback = self._build_fallback_scenes(advisory)[:max_scenes]
        problems = self._validate(fallback, advisory, skip_text_rules=True)
        if problems:
            raise ScriptValidationError(problems, total)
        return fallback

    def generate_episode_script(
        self,
        advisory: Dict[str, Any],
        max_scenes: int = 3,
        style: Optional[str] = None,
        hook_style: Optional[str] = None,
    ) -> Dict[str, Any]:
        """توليد سيناريو حلقة كاملة باللغة الإنجليزية لثغرة أمنية محددة عبر PromptOptimizer."""
        cve_id = str(advisory.get("cve_id", "CVE-Advisory"))
        prompts = self.optimizer.build_script_prompts(
            advisory=advisory,
            max_scenes=max_scenes,
            style=style,
            hook_style=hook_style,
        )

        if not self.validation_enabled:
            logger.warning("[ScriptWriter] Script fact-checking disabled by configuration.")
            scenes = self._attempt(prompts, None, max_scenes)
            if not scenes:
                logger.warning("[ScriptWriter] Using deterministic English fallback script for %s.", cve_id)
                scenes = self._build_fallback_scenes(advisory)[:max_scenes]
        else:
            scenes = self._generate_validated(advisory, prompts, max_scenes, cve_id)

        return {
            "language": self.optimizer.default_language,
            "cve_id": cve_id,
            "prompt_version": PROMPT_VERSION,
            "episode_title": f"{cve_id}: Technical Breakdown & Defense",
            "scenes": scenes,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_advisory = {
        "cve_id": "CVE-2026-124501",
        "severity": "MEDIUM",
        "cvss_score": 5.5,
        "summary": "Improper validation in file upload endpoint allows SSRF.",
    }
    writer = ScriptWriter()
    script_data = writer.generate_episode_script(sample_advisory, max_scenes=3)
    print(json.dumps(script_data, indent=2, ensure_ascii=False))