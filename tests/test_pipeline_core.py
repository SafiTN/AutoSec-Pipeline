from pathlib import Path

import yaml

from core.config_loader import load_settings, resolve_project_path
from core.prompt_optimizer import PromptOptimizer


def test_load_settings_defaults_and_types():
    settings = load_settings()

    assert isinstance(settings, dict)
    assert "ollama" in settings
    assert "nvd" in settings
    assert "prompt_optimizer" in settings
    assert "media" in settings
    assert isinstance(settings["ollama"]["model"], str)
    assert settings["ollama"]["model"].strip() != ""


def test_load_settings_custom_yaml_deep_merge(tmp_path: Path):
    custom_cfg = {
        "ollama": {
            "model": "custom-test-model:latest",
        },
        "media": {
            "fps": 30,
        },
    }
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text(yaml.safe_dump(custom_cfg), encoding="utf-8")

    merged = load_settings(str(cfg_file))

    assert merged["ollama"]["model"] == "custom-test-model:latest"
    assert merged["ollama"]["base_url"] == "http://localhost:11434"
    assert merged["media"]["fps"] == 30
    assert merged["media"]["resolution"]["width"] == 1280


def test_resolve_project_path_relative_and_absolute(tmp_path: Path):
    rel_resolved = resolve_project_path("output/last_episode_manifest.json")
    assert rel_resolved.is_absolute()
    assert rel_resolved.name == "last_episode_manifest.json"

    abs_target = tmp_path / "sample.mp4"
    assert resolve_project_path(str(abs_target)) == abs_target.resolve()


def test_prompt_optimizer_builds_valid_prompts():
    optimizer = PromptOptimizer()
    cve_sample = {
        "cve_id": "CVE-2026-99999",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Improper input validation in an example service.",
    }

    prompts = optimizer.build_script_prompts(advisory=cve_sample, max_scenes=3)

    assert isinstance(prompts, dict)
    assert "system_prompt" in prompts
    assert "user_prompt" in prompts
    assert isinstance(prompts["system_prompt"], str) and prompts["system_prompt"].strip() != ""
    assert isinstance(prompts["user_prompt"], str) and prompts["user_prompt"].strip() != ""
    combined_text = f"{prompts['system_prompt']} {prompts['user_prompt']}"
    assert "CVE-2026-99999" in combined_text
