import copy
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger("AutoSec.ConfigLoader")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"

DEFAULT_SETTINGS: Dict[str, Any] = {
    "project": {
        "name": "AutoSec-Pipeline",
        "version": "1.0.0",
        "log_level": "INFO",
    },
    "paths": {
        "output_dir": "output",
        "media_dir": "output_media",
        "default_video_filename": "cyber_episode.mp4",
        "manifest_filename": "last_episode_manifest.json",
        "covered_cves_filename": "covered_cves.json",
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "model": "qwen2.5-coder:7b",
        "timeout_sec": 120,
        "temperature": 0.2,
    },
    "nvd": {
        "api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "lookback_days": 14,
        "max_results": 10,
        "default_limit": 3,
        "timeout_sec": 20,
        "max_retries": 2,
        "allow_fallback": False,
    },
    "prompt_optimizer": {
        "language": "en",
        "style": "concise_technical",
        "default_max_scenes": 3,
        "hook_rotation": True,
        "hook_styles": ["question", "number", "scenario"],
        "max_bullets": 3,
        "max_bullet_chars": 48,
        "max_takeaway_chars": 160,
        "max_hook_words": 25,
    },
    "script_validation": {
        "enabled": True,
        "max_retries": 2,
        "forbidden_terms": [
            "payload",
            "exploit code",
            "shellcode",
            "reverse shell",
            "proof of concept",
            "poc",
            "step-by-step exploit",
            "weaponiz",
        ],
    },
    "media": {
        "tts_voice": "en-US-GuyNeural",
        "fps": 24,
        "resolution": {
            "width": 1280,
            "height": 720,
        },
    },
    "sandbox": {
        "timeout_sec": 10,
        "max_memory_mb": 256,
        "max_output_bytes": 65536,
        "max_processes": 1,
        "work_root": ".sandbox_runs",
        "allow_unlimited": False,
    },
    "harness": {
        "enabled_by_default": False,
        "max_iterations": 3,
        "target_score": 90.0,
        "pass_threshold": 80.0,
    },
}


def get_harness_config(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return the validated harness section merged over defaults.

    Raises ValueError for invalid values (never clamps silently).
    """
    cfg = _deep_merge(DEFAULT_SETTINGS["harness"], (settings or {}).get("harness") or {})
    max_iter = cfg["max_iterations"]
    if isinstance(max_iter, bool) or not isinstance(max_iter, int) or max_iter < 1:
        raise ValueError(f"harness.max_iterations must be an int >= 1, got {max_iter!r}")
    for key in ("pass_threshold", "target_score"):
        val = cfg[key]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValueError(f"harness.{key} must be a number, got {val!r}")
    if not (0 <= cfg["pass_threshold"] <= cfg["target_score"] <= 100):
        raise ValueError(
            "harness requires 0 <= pass_threshold <= target_score <= 100, got "
            f"pass_threshold={cfg['pass_threshold']!r}, target_score={cfg['target_score']!r}"
        )
    return cfg


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """دمج قاموس الإعدادات المخصصة فوق الإعدادات الافتراضية بشكل متداخِل."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _apply_env_overrides(settings: Dict[str, Any]) -> Dict[str, Any]:
    """تطبيق أي متغيرات بيئة اختيارية لتجاوز إعدادات YAML عند التشغيل."""
    env_ollama_model = os.getenv("OLLAMA_MODEL", "").strip()
    if env_ollama_model:
        settings.setdefault("ollama", {})["model"] = env_ollama_model

    env_ollama_url = os.getenv("OLLAMA_BASE_URL", "").strip()
    if env_ollama_url:
        settings.setdefault("ollama", {})["base_url"] = env_ollama_url

    return settings


def resolve_project_path(relative_or_abs: str) -> Path:
    """تحويل المسار النسبي إلى مسار مطلق مبني على جذر المشروع."""
    path = Path(relative_or_abs)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def load_settings(config_path: Optional[str] = None) -> Dict[str, Any]:
    """تحميل إعدادات المشروع من config/settings.yaml مع الرجوع للقيم الافتراضية بأمان."""
    target_path = Path(config_path).resolve() if config_path else DEFAULT_SETTINGS_PATH
    settings = copy.deepcopy(DEFAULT_SETTINGS)

    if target_path.exists():
        try:
            with target_path.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                settings = _deep_merge(settings, loaded)
                logger.debug("[ConfigLoader] Loaded settings from %s", target_path)
            else:
                logger.warning(
                    "[ConfigLoader] Settings file %s did not contain a YAML mapping; using defaults.",
                    target_path,
                )
        except Exception as exc:
            logger.warning(
                "[ConfigLoader] Failed to parse %s (%s); falling back to defaults.",
                target_path,
                exc,
            )
    else:
        logger.info(
            "[ConfigLoader] %s not found; using built-in DEFAULT_SETTINGS.",
            target_path,
        )

    return _apply_env_overrides(settings)


if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO)
    cfg = load_settings()
    print(json.dumps(cfg, indent=2, ensure_ascii=False))