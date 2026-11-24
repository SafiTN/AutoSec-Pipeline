import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AutoSec.PromptOptimizer")


class PromptOptimizer:
    """محسّن ومُوحّد للـ Prompts الخاصة بكتابة السيناريوهات والوكيل البرمجي."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {}
        opt_cfg = self.settings.get("prompt_optimizer", {})
        self.default_language: str = str(opt_cfg.get("language", "en")).strip() or "en"
        self.default_style: str = str(opt_cfg.get("style", "concise_technical")).strip()

    @staticmethod
    def clean_text(text: str) -> str:
        """تنظيف النص من الأسطر الفارغة المتكررة والمسافات الزائدة."""
        if not text:
            return ""
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        normalized = re.sub(r"\n{3,}", "\n\n", normalized)
        normalized = re.sub(r"[ \t]{2,}", " ", normalized)
        return normalized.strip()

    @staticmethod
    def sanitize_for_tts_hints(text: str) -> str:
        """تقليل الرموز الخاصة التي قد تربك محركات TTS مثل Edge-TTS."""
        if not text:
            return ""
        cleaned = re.sub(r"[`*_~#]+", "", text)
        return PromptOptimizer.clean_text(cleaned)

    def build_script_prompts(
        self,
        advisory: Dict[str, Any],
        max_scenes: int = 3,
        style: Optional[str] = None,
    ) -> Dict[str, str]:
        """بناء system_prompt و user_prompt محسنين لإنتاج سيناريو فيديو إنجليزي بصيغة JSON."""
        active_style = (style or self.default_style).lower()
        safe_scenes = max(1, min(int(max_scenes), 8))

        style_instruction = (
            "Keep each narration to 2-3 crisp, natural spoken sentences suitable for voiceover."
            if active_style == "concise_technical"
            else "Provide clear, accurate technical explanations with practical defensive takeaways."
        )

        system_prompt = self.clean_text(
            f"""
You are a senior cybersecurity technical educator producing {self.default_language.upper()} YouTube scripts.
Return ONLY a single valid JSON object with a top-level "scenes" list.
Each element in "scenes" must be an object with exact keys:
- "title": short scene heading (string)
- "narration": natural spoken English text for Edge-TTS (string, plain text without markdown formatting)
- "visual_cue": concise technical visual description for video slides/diagrams (string)

Rules:
1. {style_instruction}
2. Avoid markdown code fences (```json), preambles, or trailing commentary.
3. Ensure all technical terms, CVE IDs, and severity ratings match the input advisory accurately.
""".strip()
        )

        cve_id = self.sanitize_for_tts_hints(str(advisory.get("cve_id", "CVE-Advisory")))
        severity = str(advisory.get("severity", "UNKNOWN")).upper()
        cvss_score = advisory.get("cvss_score", "N/A")
        published = advisory.get("published", "N/A")
        summary = self.sanitize_for_tts_hints(str(advisory.get("summary", "")))

        user_prompt = self.clean_text(
            f"""
Generate a {safe_scenes}-scene English technical video script for this advisory:
- CVE ID: {cve_id}
- Severity: {severity}
- CVSS Score: {cvss_score}
- Published: {published}
- Summary: {summary}

Structure the {safe_scenes} scenes logically from vulnerability overview and root cause/impact to concrete mitigation and verification.
""".strip()
        )

        logger.debug("[PromptOptimizer] Built script prompts for %s (%d scenes).", cve_id, safe_scenes)
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        }

    def optimize_agent_prompt(
        self,
        base_prompt: str,
        feedback: Optional[str] = None,
        previous_score: Optional[float] = None,
        extra_constraints: Optional[List[str]] = None,
    ) -> str:
        """تحسين موجه الوكيل البرمجي بناءً على ملاحظات التقييم السابقة والقيود الإضافية."""
        cleaned_base = self.clean_text(base_prompt)
        additions: List[str] = []

        if previous_score is not None and previous_score < 100.0:
            additions.append(
                f"Previous evaluation score was {previous_score:.1f}/100. "
                "Fix every issue thoroughly, preserve exact required function/class signatures, and handle edge cases cleanly."
            )

        if feedback and feedback.strip():
            additions.append(f"Evaluator feedback to address:\n{self.clean_text(feedback)}")

        if extra_constraints:
            formatted_constraints = "\n".join(
                f"- {self.clean_text(c)}" for c in extra_constraints if c and c.strip()
            )
            if formatted_constraints:
                additions.append(f"Additional constraints:\n{formatted_constraints}")

        if not additions:
            return cleaned_base

        optimized = f"{cleaned_base}\n\n" + "\n\n".join(additions)
        return self.clean_text(optimized)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    optimizer = PromptOptimizer()

    sample = {
        "cve_id": "CVE-2026-124501",
        "severity": "MEDIUM",
        "cvss_score": 5.5,
        "published": "2026-11-09",
        "summary": "Improper validation in file upload endpoint allows SSRF.",
    }
    prompts = optimizer.build_script_prompts(sample, max_scenes=3)
    print("--- SYSTEM PROMPT ---")
    print(prompts["system_prompt"])
    print("\n--- USER PROMPT ---")
    print(prompts["user_prompt"])