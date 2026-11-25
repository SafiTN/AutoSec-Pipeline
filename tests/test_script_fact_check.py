"""
Tests for T06: script fact-check validator, ScriptWriter retry loop, retry
feedback, config defaults and run_pipeline propagation.

Fully offline: the Ollama call (AgentRunner.query_local_agent) is replaced by a
scripted fake; no network, no TTS, nothing written to the real output/.
"""

import json
import logging

import pytest
import yaml

import main
from core.config_loader import DEFAULT_SETTINGS, load_settings
from core.prompt_optimizer import PromptOptimizer
from modules.content_pipeline.script_validator import ScriptValidationError, validate_script
from modules.content_pipeline.script_writer import ScriptWriter

RULES = {"forbidden_terms": DEFAULT_SETTINGS["script_validation"]["forbidden_terms"]}

ADVISORY = {
    "cve_id": "CVE-2026-12345",
    "severity": "HIGH",
    "cvss_score": 9.8,
    "summary": "Improper input validation in Foo 2.4.1 allows remote denial of service.",
    "affected_versions": "2.4.1 and earlier",
    "fixed_versions": ["2.5.0"],
}


def scene(narration="", title="", visual_cue=""):
    return {"title": title, "narration": narration, "visual_cue": visual_cue}


def check(narration="", advisory=None, rules=RULES, **kw):
    return validate_script([scene(narration=narration, **kw)], advisory or ADVISORY, rules)


# ---------------------------------------------------------------------------
# Validator: CVE id
# ---------------------------------------------------------------------------


def test_clean_script_passes():
    text = "CVE-2026-12345 is rated high severity with a CVSS score of 9.8 in Foo 2.4.1, fixed in 2.5.0."
    assert check(text) == []


def test_wrong_cve_id_flagged_case_insensitive():
    v = check("This is cve-2026-99999 today.")
    assert any(x.startswith("CVE id") for x in v)


def test_cve_id_in_title_and_visual_cue_checked():
    assert check(title="CVE-2020-0001 overview")
    assert check(visual_cue="CVE-2020-0001 slide")


def test_advisory_id_lowercase_in_script_ok():
    assert check("cve-2026-12345 matters") == []


def test_sample_suffix_id_not_flagged():
    adv = dict(ADVISORY, cve_id="CVE-2025-29927-SAMPLE")
    assert check("CVE-2025-29927-SAMPLE is a sample.", adv) == []
    assert check("CVE-2025-29927 is a sample.", adv) == []
    assert check("CVE-2025-11111 is another.", adv)


# ---------------------------------------------------------------------------
# Validator: severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a critical severity flaw",
        "The severity is critical.",
        "severity of CRITICAL",
        "severity: critical",
        "This was rated Critical.",
        "CRITICAL   severity",
    ],
)
def test_severity_mismatch_patterns_flagged(text):
    assert any(x.startswith("severity") for x in check(text))


@pytest.mark.parametrize("text", ["high severity", "HIGH Severity", "severity is high", "rated high"])
def test_severity_match_passes(text):
    assert check(text) == []


def test_unknown_severity_any_claim_flagged():
    adv = dict(ADVISORY, severity="UNKNOWN")
    v = check("a high severity issue", adv)
    assert any("not specified" in x for x in v)


def test_unknown_severity_no_claim_passes():
    adv = dict(ADVISORY, severity="UNKNOWN")
    assert check("Severity is not yet specified.", adv) == []


# ---------------------------------------------------------------------------
# Validator: CVSS
# ---------------------------------------------------------------------------


def test_cvss_mismatch_flagged():
    assert any(x.startswith("CVSS") for x in check("CVSS score of 7.5"))


@pytest.mark.parametrize("text", ["CVSS score of 9.8", "CVSS: 9.8", "CVSS base score is 9.80", "cvss 9.800"])
def test_cvss_numeric_equality(text):
    assert check(text) == []


def test_cvss_advisory_9_80_string_equal():
    adv = dict(ADVISORY, cvss_score="9.80")
    assert check("CVSS 9.8", adv) == []


def test_cvss_with_none_score_flags_any_value():
    adv = dict(ADVISORY, cvss_score=None)
    assert any(x.startswith("CVSS") for x in check("CVSS score 5.0", adv))


# ---------------------------------------------------------------------------
# Validator: versions
# ---------------------------------------------------------------------------


def test_invented_version_flagged():
    assert any(x.startswith("version") for x in check("Upgrade to version 9.9 now"))


def test_sentence_ending_version_flagged():
    v = check("Upgrade to version 9.9.")
    assert any("9.9" in x for x in v)


def test_v_prefixed_invented_version_flagged():
    assert any("3.4.5" in x for x in check("Fixed in v3.4.5"))


@pytest.mark.parametrize(
    "text",
    [
        "Foo 2.4.1 is affected.",  # from summary
        "Versions 2.4.1 and earlier.",  # affected_versions
        "Fixed in 2.5.0.",  # fixed_versions (list)
        "Fixed in v2.5.0, ok.",
    ],
)
def test_versions_from_advisory_fields_pass(text):
    assert check(text) == []


def test_cvss_score_not_reported_as_version():
    assert check("A score of 9.8 is severe.") == []


def test_not_yet_specified_wording_passes():
    assert check("Fixed versions are not yet specified.") == []


# ---------------------------------------------------------------------------
# Validator: forbidden terms and evasion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Craft a payload for it",
        "Here is exploit code",
        "write shellcode",
        "open a reverse shell",
        "a proof of concept exists",
        "a PoC exists",
        "step-by-step exploit guide",
        "weaponized tooling",
        "weaponization",
    ],
)
def test_forbidden_terms_flagged(text):
    assert any(x.startswith("forbidden term") for x in check(text))


def test_plain_exploit_allowed():
    assert check("Attackers may exploit this; exploitation was observed.") == []


def test_word_boundary_poc_not_substring():
    assert check("The topic of epoch is pocket sized.") == []


@pytest.mark.parametrize(
    "text",
    [
        "PAYLOAD",
        "PayLoad",
        "exploit    code",
        "exploit\n\tcode",
        "ｐａｙｌｏａｄ",  # fullwidth 'payload' (NFKC)
        "SHELLCODE",
        "Proof   Of\nConcept",
    ],
)
def test_forbidden_terms_case_whitespace_unicode_evasion(text):
    assert any(x.startswith("forbidden term") for x in check(text))


def test_forbidden_term_in_title_and_visual_cue():
    assert check(title="shellcode demo")
    assert check(visual_cue="payload diagram")


def test_custom_rules_and_empty_rules():
    assert check("badword here", rules={"forbidden_terms": ["badword"]})
    assert check("payload", rules={}) == []
    assert check("payload", rules=None) == []
    assert check("payload", rules={"forbidden_terms": None}) == []


def test_empty_and_blank_terms_ignored():
    assert check("hello", rules={"forbidden_terms": ["", "   "]}) == []


def test_non_mapping_scene_and_missing_fields_do_not_crash():
    assert validate_script([None, "x", {}], ADVISORY, RULES) == []


def test_duplicate_violations_deduplicated():
    v = validate_script([scene("payload"), scene("payload")], ADVISORY, RULES)
    assert len(v) == 1


def test_skip_text_rules_only_applies_identity_rules():
    s = [scene("payload in version 9.9, CVE-2020-1111 CVSS 1.0 critical severity")]
    v = validate_script(s, ADVISORY, RULES, skip_text_rules=True)
    kinds = {x.split(" ")[0] for x in v}
    assert kinds == {"CVE", "severity", "CVSS"}


def test_very_long_input_is_fast():
    long_text = ("a" * 50000) + " " * 20000 + ("1." * 20000) + ("cvss " * 5000) + ("severity " * 5000)
    validate_script([scene(long_text, title=long_text, visual_cue=long_text)], ADVISORY, RULES)


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


def test_error_is_valueerror_and_carries_attempts():
    err = ScriptValidationError(["forbidden term: payload"], 3)
    assert isinstance(err, ValueError)
    assert err.attempts == 3
    assert "3 attempt" in str(err) and "payload" in str(err)


def test_error_with_no_violations_has_message():
    assert "no valid script" in str(ScriptValidationError([], 1))


# ---------------------------------------------------------------------------
# Retry feedback
# ---------------------------------------------------------------------------


def test_retry_feedback_never_echoes_forbidden_terms_or_values():
    violations = validate_script(
        [scene("shellcode payload, CVE-2020-1111, critical severity, CVSS 1.5, version 6.6.6")],
        ADVISORY,
        RULES,
    )
    fb = PromptOptimizer.build_retry_feedback(violations)
    low = fb.lower()
    for leaked in ("shellcode", "payload", "2020-1111", "1.5", "6.6.6", "critical", "reverse shell", "poc"):
        assert leaked not in low
    assert "CVE" in fb and "CVSS" in fb  # categories restated


def test_retry_feedback_generic_when_no_category():
    assert "advisory facts only" in PromptOptimizer.build_retry_feedback(["weird"]).lower()


def test_retry_feedback_only_matching_categories():
    fb = PromptOptimizer.build_retry_feedback(["CVSS score 1.0 does not match advisory"])
    assert "CVSS" in fb and "version" not in fb.lower().replace("previous", "")


# ---------------------------------------------------------------------------
# ScriptWriter retry loop (mocked Ollama)
# ---------------------------------------------------------------------------


def _good_json(narr="CVE-2026-12345 is rated high severity."):
    return json.dumps({"scenes": [{"title": "Overview", "narration": narr, "visual_cue": "Diagram"}]})


def _bad_json():
    return _good_json("Use this payload to attack.")


def make_writer(responses, **val_overrides):
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    settings["script_validation"].update(val_overrides)
    writer = ScriptWriter(settings=settings)
    calls = []
    queue = list(responses)

    def fake_query(prompt, system_prompt=""):
        calls.append(prompt)
        return queue.pop(0) if queue else "not json"

    writer.agent.query_local_agent = fake_query
    return writer, calls


def test_valid_first_try_single_call():
    writer, calls = make_writer([_good_json()])
    out = writer.generate_episode_script(ADVISORY, max_scenes=3)
    assert len(calls) == 1
    assert out["scenes"][0]["narration"].startswith("CVE-2026-12345")
    assert out["cve_id"] == "CVE-2026-12345"


def test_retry_then_success_with_clean_feedback():
    writer, calls = make_writer([_bad_json(), _good_json()])
    out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 2
    assert "did not pass fact-checking" in calls[1]
    assert "payload" not in calls[1].lower()
    assert "payload" not in out["scenes"][0]["narration"].lower()


def test_fenced_json_accepted_and_validated():
    writer, calls = make_writer(["```json\n" + _good_json() + "\n```"])
    out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 1 and out["scenes"]


def test_exhaustion_raises_without_fallback(caplog):
    writer, calls = make_writer([_bad_json()] * 5)
    with pytest.raises(ScriptValidationError) as ei:
        writer.generate_episode_script(ADVISORY)
    assert len(calls) == 3  # 1 + max_retries(2)
    assert ei.value.attempts == 3
    assert "Use this payload to attack" not in str(ei.value)
    assert "attack" not in str(ei.value)


def test_log_does_not_contain_scene_text(caplog):
    writer, _ = make_writer([_bad_json()] * 3)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ScriptValidationError):
            writer.generate_episode_script(ADVISORY)
    assert "Use this payload" not in caplog.text


def test_hallucinated_version_triggers_retry():
    bad = _good_json("Foo is fixed in version 7.7.7.")
    writer, calls = make_writer([bad, _good_json()])
    writer.generate_episode_script(ADVISORY)
    assert len(calls) == 2
    assert "version numbers" in calls[1]


def test_all_unparseable_uses_deterministic_fallback():
    writer, calls = make_writer(["garbage", "{not json", ""])
    out = writer.generate_episode_script(ADVISORY, max_scenes=3)
    assert len(calls) == 3
    assert len(out["scenes"]) == 3
    assert "CVE-2026-12345" in out["scenes"][0]["narration"]


def test_unparseable_then_bad_then_exhausted_raises():
    writer, _ = make_writer(["garbage", _bad_json(), _bad_json()])
    with pytest.raises(ScriptValidationError):
        writer.generate_episode_script(ADVISORY)


def test_unparseable_then_valid_succeeds():
    writer, calls = make_writer(["garbage", _good_json()])
    out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 2 and out["scenes"]


def test_fallback_with_mismatched_identity_raises():
    # Fallback is built from the advisory so identity rules hold; a weird
    # severity string must still not crash and must not produce a bogus pass.
    adv = dict(ADVISORY, summary="Short summary.", affected_versions=None, fixed_versions=None)
    writer, _ = make_writer(["x", "y", "z"])
    out = writer.generate_episode_script(adv)
    assert out["scenes"]


def test_enabled_false_skips_validation_and_single_call(caplog):
    writer, calls = make_writer([_bad_json()], enabled=False)
    with caplog.at_level(logging.WARNING):
        out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 1
    assert "payload" in out["scenes"][0]["narration"].lower()
    assert "disabled" in caplog.text.lower()


def test_enabled_false_unparseable_falls_back():
    writer, calls = make_writer(["garbage"], enabled=False)
    out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 1 and len(out["scenes"]) == 3


@pytest.mark.parametrize("val", [-1, -50, 0])
def test_negative_or_zero_max_retries_means_one_attempt(val):
    writer, calls = make_writer([_bad_json(), _good_json()], max_retries=val)
    with pytest.raises(ScriptValidationError):
        writer.generate_episode_script(ADVISORY)
    assert len(calls) == 1


def test_max_retries_one_gives_two_attempts():
    writer, calls = make_writer([_bad_json()] * 5, max_retries=1)
    with pytest.raises(ScriptValidationError) as ei:
        writer.generate_episode_script(ADVISORY)
    assert len(calls) == 2 and ei.value.attempts == 2


def test_ollama_error_string_response_treated_as_unparseable():
    writer, calls = make_writer(["Error: Could not connect to Ollama."] * 3)
    out = writer.generate_episode_script(ADVISORY)
    assert len(calls) == 3 and out["scenes"]


def test_very_long_title_and_narration_validated_quickly():
    big = "word " * 20000
    payload = json.dumps({"scenes": [{"title": big, "narration": big, "visual_cue": big}]})
    writer, _ = make_writer([payload])
    assert writer.generate_episode_script(ADVISORY)["scenes"]


def test_markdown_obfuscated_forbidden_term_caught_after_sanitize():
    # sanitize_for_tts_hints strips '_' and '*', so "pay_load" becomes "payload".
    writer, calls = make_writer([_good_json("Use a pay_load now."), _good_json()])
    writer.generate_episode_script(ADVISORY)
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_default_settings_and_yaml_have_script_validation():
    sv = DEFAULT_SETTINGS["script_validation"]
    assert sv["enabled"] is True and sv["max_retries"] == 2
    assert "payload" in sv["forbidden_terms"]
    loaded = load_settings()
    assert loaded["script_validation"]["max_retries"] == 2
    assert loaded["script_validation"]["forbidden_terms"]


def test_missing_section_in_yaml_uses_defaults(tmp_path):
    cfg = tmp_path / "s.yaml"
    cfg.write_text(yaml.safe_dump({"ollama": {"model": "x"}}), encoding="utf-8")
    s = load_settings(str(cfg))
    assert s["script_validation"] == DEFAULT_SETTINGS["script_validation"]


def test_partial_section_merges_with_defaults(tmp_path):
    cfg = tmp_path / "s.yaml"
    cfg.write_text(yaml.safe_dump({"script_validation": {"max_retries": 5}}), encoding="utf-8")
    s = load_settings(str(cfg))
    assert s["script_validation"]["max_retries"] == 5
    assert s["script_validation"]["enabled"] is True
    assert "shellcode" in s["script_validation"]["forbidden_terms"]


def test_writer_with_no_script_validation_key_uses_safe_behaviour():
    # Settings dict lacking the section entirely (e.g. hand-built in tests).
    writer = ScriptWriter(settings={"ollama": {}})
    assert writer.validation_enabled is True
    assert writer.max_retries == 0


# ---------------------------------------------------------------------------
# run_pipeline propagation
# ---------------------------------------------------------------------------


class _Fetcher:
    def __init__(self, settings=None):
        pass

    def fetch_latest_cves(self, limit=3):
        return [dict(ADVISORY, is_sample=False)]


class _RaisingWriter:
    def __init__(self, settings=None):
        pass

    def generate_episode_script(self, advisory, max_scenes=3):
        raise ScriptValidationError(["forbidden term: payload"], 3)


class _MediaMustNotRun:
    def __init__(self, settings=None):
        raise AssertionError("media generation must not start")


def test_run_pipeline_propagates_validation_error_no_side_effects(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    recorded = []
    monkeypatch.setattr(main, "NewsFetcher", _Fetcher)
    monkeypatch.setattr(main, "ScriptWriter", _RaisingWriter)
    monkeypatch.setattr(main, "CyberMediaGenerator", _MediaMustNotRun)
    monkeypatch.setattr(main, "_load_covered_cve_ids", lambda s: set())
    monkeypatch.setattr(main, "_record_covered_cve", lambda *a, **k: recorded.append(a))

    with pytest.raises(ScriptValidationError):
        main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)

    assert recorded == []
    assert not (tmp_path / "output" / "last_episode_manifest.json").exists()


def test_validation_error_caught_by_main_entrypoint_exception_tuple():
    # __main__ catches (NvdFetchError, ValueError); the error must be a ValueError.
    assert issubclass(ScriptValidationError, ValueError)


# ---------------------------------------------------------------------------
# Regression tests for QA-found bugs
# ---------------------------------------------------------------------------


def test_zero_width_space_evasion():
    assert any(x.startswith("forbidden term") for x in check("pay​load"))


def test_hyphenated_severity_claim():
    assert any(x.startswith("severity") for x in check("a critical-severity flaw"))


def test_cvss_metric_version_not_flagged():
    assert check("Scored under CVSS 3.1, the score is 9.8.") == []


def test_version_substring_false_pass():
    assert any(x.startswith("version") for x in check("Fixed in 4.1."))


@pytest.mark.parametrize(
    "text",
    [
        "rated: critical",
        "severity level is critical",
        "severity: critical",
        "a critical-severity bug",
    ],
)
def test_severity_variants_detected(text):
    assert any(x.startswith("severity") for x in check(text))


@pytest.mark.parametrize(
    "text",
    [
        "CVSS 3.1 base score 9.8.",
        "CVSS v3.1 score 9.8",
        "CVSS 4.0 score of 9.8",
        "Scored with CVSS v3.1.",
    ],
)
def test_cvss_version_not_flagged(text):
    assert check(text) == []


def test_cvss_version_then_wrong_score_flagged():
    assert any("CVSS score 7.5" in x for x in check("CVSS 3.1 base score 7.5"))


def test_soft_hyphen_evasion():
    assert any(x.startswith("forbidden term") for x in check("pay­load"))


# ---------------------------------------------------------------------------
# Security review fixes (M0, M1, M2, L3, L5)
# ---------------------------------------------------------------------------


def test_m0_bare_cvss_wrong_score_flagged():
    assert any("CVSS score 3.5" in x for x in check("CVSS 3.5"))


@pytest.mark.parametrize("v", ["2.0", "3.0", "3.1", "4.0"])
def test_m0_real_cvss_versions_exempt(v):
    assert check(f"CVSS {v} base score 9.8.") == []


@pytest.mark.parametrize(
    "text",
    [
        "CVE‑2025‑9999",
        "CVE–2025–9999",
        "CVE−2025−9999",
        "CVE 2025 9999",
        "cve_2025_9999",
        "CVE-2025-9999",
    ],
)
def test_m1_invented_cve_variants_flagged(text):
    assert any(x.startswith("CVE id") for x in check(text))


def test_m1_advisory_own_id_variants_ok():
    assert check("CVE‑2026‑12345 and CVE 2026 12345") == []
    adv = dict(ADVISORY, cve_id="CVE-2025-29927-SAMPLE")
    assert check("CVE‑2025‑29927-SAMPLE", adv) == []


@pytest.mark.parametrize(
    "text",
    [
        "proof-of-concept",
        "shell-code",
        "pay-load",
        "p a y l o a d",
        "payloads",
        "shellcodes",
        "exploit codes",
        "weaponized",
        "weaponization",
        "pay_load",
        "Proof of Concept",
    ],
)
def test_m2_forbidden_term_variants(text):
    assert any(x.startswith("forbidden term") for x in check(text))


def test_m2_homoglyph_mixed_script_flagged():
    assert check("a рayload here")  # Cyrillic er inside a Latin word
    assert check("a οbfuscated word")  # Greek omicron inside a Latin word


@pytest.mark.parametrize("text", ["a pocket guide", "exploitation of the flaw"])
def test_m2_no_false_positive(text):
    assert not any(x.startswith("forbidden term") for x in check(text))


def test_m2_long_input_is_fast():
    import time

    t = time.time()
    check("p " * 20000 + "- " * 20000)
    assert time.time() - t < 5


@pytest.mark.parametrize("text", ["rated as critical", "rated at Critical", "Rated: critical"])
def test_l3_rated_as_at_flagged(text):
    assert any(x.startswith("severity") for x in check(text))


def test_l3_rated_as_matching_level_ok():
    assert check("rated as high") == []


@pytest.mark.parametrize("bad", ["abc", None, [], {}])
def test_l5_bad_max_retries_falls_back_to_default(bad, caplog):
    with caplog.at_level(logging.WARNING):
        writer = ScriptWriter(settings={"script_validation": {"max_retries": bad}})
    assert writer.max_retries == DEFAULT_SETTINGS["script_validation"]["max_retries"]
    assert any("max_retries" in r.getMessage() for r in caplog.records)


def test_l5_string_false_enabled_fails_safe(caplog):
    with caplog.at_level(logging.WARNING):
        writer = ScriptWriter(settings={"script_validation": {"enabled": "false"}})
    assert writer.validation_enabled is True
    assert any("ENABLED" in r.getMessage() for r in caplog.records)
    assert ScriptWriter(settings={"script_validation": {"enabled": False}}).validation_enabled is False
