"""T12: ScriptWriter edge cases (Ollama mocked; offline)."""

import json
import logging

import pytest

from modules.content_pipeline.script_validator import ScriptValidationError
from modules.content_pipeline.script_writer import ScriptWriter, normalize_scenes

ADV = {
    "cve_id": "CVE-2026-12345",
    "severity": "HIGH",
    "cvss_score": 8.1,
    "summary": "Improper input validation in Foo allows denial of service.",
}
GOOD = {
    "scenes": [
        {
            "title": "T",
            "narration": "CVE-2026-12345 is rated high severity.",
            "key_takeaway": "Patch.",
            "on_screen_bullets": ["a"],
            "visual_cue": "v",
        }
    ]
}
extract = ScriptWriter._extract_json_payload


def _writer(queue, **rules):
    w = ScriptWriter(settings={"script_validation": rules})
    calls = []

    def fake(prompt, system_prompt=None):
        calls.append(prompt)
        return queue[min(len(calls) - 1, len(queue) - 1)]

    w.agent.query_local_agent = fake
    w.calls = calls
    return w


@pytest.mark.parametrize(
    "raw", [None, "", "not json at all", "[1, 2]", '{"scenes": "x"}', '{"other": []}', "prose {broken: json} prose"]
)
def test_extract_rejects_garbage(raw):
    assert extract(raw) is None


def test_extract_plain_fenced_and_prose_wrapped():
    body = json.dumps(GOOD)
    assert extract(body) == GOOD
    assert extract(f"```json\n{body}\n```") == GOOD
    assert extract(f"```\n{body}\n```") == GOOD
    assert extract(f"Sure! Here you go:\n{body}\nHope it helps.") == GOOD


def test_extract_prose_with_non_scenes_object_is_none():
    assert extract('Here: {"a": 1} done') is None


@pytest.mark.parametrize("val,exp", [(2, 2), ("3", 3), (-4, 0), (1.9, 1)])
def test_parse_max_retries(val, exp):
    assert ScriptWriter._parse_max_retries(val) == exp


@pytest.mark.parametrize("val", ["x", None, [1]])
def test_parse_max_retries_invalid_uses_default(val):
    got = ScriptWriter._parse_max_retries(val)
    assert isinstance(got, int) and got >= 0


@pytest.mark.parametrize("val,exp", [(True, True), (False, False), ("false", True), (0, True), (None, True)])
def test_parse_enabled_fail_safe(val, exp):
    assert ScriptWriter._parse_enabled(val) is exp


def test_retry_exhaustion_raises_after_total_attempts():
    bad = json.dumps({"scenes": [{"narration": "CVE-2026-99999 is rated high."}]})
    w = _writer([bad], max_retries=2)
    with pytest.raises(ScriptValidationError):
        w.generate_episode_script(ADV)
    assert len(w.calls) == 3
    assert "CVE-2026-99999" in w.calls[1] or len(w.calls[1]) > len(w.calls[0])  # feedback appended


def test_retry_then_success_returns_scenes():
    bad = json.dumps({"scenes": [{"narration": "CVE-2026-99999 is rated high."}]})
    w = _writer([bad, json.dumps(GOOD)], max_retries=1)
    out = w.generate_episode_script(ADV)
    assert out["cve_id"] == "CVE-2026-12345" and len(w.calls) == 2
    assert out["scenes"][0]["narration"].startswith("CVE-2026-12345")


def test_all_unparseable_uses_fallback_with_advisory_facts_only(caplog):
    w = _writer(["garbage"], max_retries=1)
    with caplog.at_level(logging.WARNING):
        out = w.generate_episode_script(ADV, max_scenes=3)
    assert len(w.calls) == 2
    text = json.dumps(out["scenes"])
    assert "CVE-2026-12345" in text and "8.1" in text and "HIGH" in text
    assert "not yet specified" in out["scenes"][2]["key_takeaway"]
    assert "deterministic fallback" in caplog.text


def test_fallback_truncates_to_max_scenes():
    w = _writer(["garbage"], max_retries=0)
    assert len(w.generate_episode_script(ADV, max_scenes=1)["scenes"]) == 1


def test_fallback_scenes_with_sparse_advisory_do_not_invent_values():
    w = _writer(["x"])
    scenes = w._build_fallback_scenes({"cve_id": "CVE-2026-1", "severity": "UNKNOWN", "cvss_score": None})
    text = json.dumps(scenes)
    assert "CVE-2026-1" in text
    assert "9." not in text and "CRITICAL" not in text


def test_validation_disabled_unparseable_falls_back_without_retry():
    w = _writer(["garbage"], enabled=False)
    out = w.generate_episode_script(ADV)
    assert len(w.calls) == 1 and len(out["scenes"]) == 3


def test_validation_disabled_passes_model_scenes_through():
    w = _writer([f"```json\n{json.dumps(GOOD)}\n```"], enabled=False)
    out = w.generate_episode_script(ADV)
    assert out["scenes"][0]["title"] == "T"


def test_normalize_long_title_bullets_and_junk():
    w = ScriptWriter(settings={})
    long = "word " * 200
    scenes = normalize_scenes(
        [
            {"title": long, "narration": "Narration here.", "on_screen_bullets": [long] * 10 + [5, None]},
            "junk",
            {"narration": 5},
            {"narration": "   "},
        ],
        5,
        w.optimizer,
    )
    assert len(scenes) == 1
    sc = scenes[0]
    assert len(sc["on_screen_bullets"]) <= w.optimizer.max_bullets
    assert all(len(b) <= w.optimizer.max_bullet_chars for b in sc["on_screen_bullets"])
    assert sc["key_takeaway"]


def test_normalize_non_list_and_zero_max():
    w = ScriptWriter(settings={})
    assert normalize_scenes(None, 3, w.optimizer) == []
    assert normalize_scenes([{"narration": "x."}], 0, w.optimizer) == []


def test_normalize_strips_zero_width_chars():
    w = ScriptWriter(settings={})
    out = normalize_scenes([{"narration": "Pa​tch now."}], 3, w.optimizer)
    assert "​" not in out[0]["narration"]
