import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from core.agent_runner import AgentRunner
from core.config_loader import load_settings
from core.prompt_optimizer import PromptOptimizer
from modules.content_pipeline.script_validator import ScriptValidationError, validate_script

logger = logging.getLogger("AutoSec.ScriptWriter")


class ScriptWriter:
    """مولد سيناريوهات الفيديو التقنية باللغة الإنجليزية انطلاقاً من بيانات الثغرات الأمنية."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        self.agent = AgentRunner(settings=self.settings)
        self.optimizer = PromptOptimizer(settings=self.settings)
        rules = dict(self.settings.get("script_validation", {}) or {})
        self.validation_rules: Dict[str, Any] = rules
        self.validation_enabled: bool = bool(rules.get("enabled", True))
        self.max_retries: int = max(0, int(rules.get("max_retries", 0)))

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
                    f"Today we examine {cve_id}, a security advisory rated {severity} with a CVSS score of {score}. "
                    f"Understanding how this flaw behaves helps engineering teams prioritize patching and exposure checks."
                ),
                "visual_cue": f"Title card showing {cve_id} and CVSS {score} ({severity})",
            },
            {
                "title": "Technical Impact & Root Cause",
                "narration": (
                    f"At a technical level, {short_summary}. "
                    f"Attackers who exploit conditions like this often target unvalidated inputs, trust boundaries, or misconfigured routing."
                ),
                "visual_cue": "Architecture diagram highlighting trust boundary and request flow",
            },
            {
                "title": "Defensive Mitigation & Hardening",
                "narration": (
                    "To defend against this class of vulnerability, apply official vendor patches promptly and enforce strict input validation. "
                    "Always verify security controls in an isolated test environment before rolling changes into production."
                ),
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
        scenes: List[Dict[str, str]] = []
        if parsed:
            for idx, sc in enumerate(parsed["scenes"][:max_scenes], start=1):
                if isinstance(sc, dict) and sc.get("narration"):
                    clean_narration = self.optimizer.sanitize_for_tts_hints(str(sc["narration"]))
                    if clean_narration:
                        scenes.append(
                            {
                                "title": self.optimizer.clean_text(str(sc.get("title") or f"Scene {idx}")),
                                "narration": clean_narration,
                                "visual_cue": self.optimizer.clean_text(
                                    str(sc.get("visual_cue") or "Technical security slide")
                                ),
                            }
                        )
        return scenes or None

    def _validate(self, scenes: List[Dict[str, str]], advisory: Dict[str, Any]) -> List[str]:
        return validate_script(scenes, advisory, self.validation_rules)

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
        problems = validate_script(fallback, advisory, self.validation_rules, skip_text_rules=True)
        if problems:
            raise ScriptValidationError(problems, total)
        return fallback

    def generate_episode_script(
        self,
        advisory: Dict[str, Any],
        max_scenes: int = 3,
        style: Optional[str] = None,
    ) -> Dict[str, Any]:
        """توليد سيناريو حلقة كاملة باللغة الإنجليزية لثغرة أمنية محددة عبر PromptOptimizer."""
        cve_id = str(advisory.get("cve_id", "CVE-Advisory"))
        prompts = self.optimizer.build_script_prompts(
            advisory=advisory,
            max_scenes=max_scenes,
            style=style,
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