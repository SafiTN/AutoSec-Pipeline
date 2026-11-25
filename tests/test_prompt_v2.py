"""T07 prompt v2: prompt rules, hook selection, scene normalization, validator integration.

Fully offline; the Ollama call is replaced by a scripted fake.
"""

import json

import pytest

from core.config_loader import DEFAULT_SETTINGS
from core.prompt_optimizer import PROMPT_VERSION, PromptOptimizer
from modules.content_pipeline.script_validator import ScriptValidationError
from modules.content_pipeline.script_writer import ScriptWriter, normalize_scenes

ADVISORY = {
    "cve_id": "CVE-2026-12345",
    "severity": "HIGH",
    "cvss_score": 9.8,
    "summary": "Improper input validation in Foo 2.4.1 allows remote denial of service.",
}


def settings(**opt_overrides):
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    s["prompt_optimizer"].update(opt_overrides)
    return s


def opt(**kw):
    return PromptOptimizer(settings=settings(**kw))


def sc(**kw):
    base = {
        "title": "T",
        "narration": "CVE-2026-12345 is rated high severity.",
        "key_takeaway": "Patch soon.",
        "on_screen_bullets": ["a", "b"],
        "visual_cue": "v",
    }
    base.update(kw)
    return base


# --- prompt rules -----------------------------------------------------------


def test_system_prompt_rules_present():
    p = opt().build_script_prompts(ADVISORY)["system_prompt"]
    low = p.lower()
    assert "scene 1 is a hook" in low
    assert "defensive only" in low
    assert "do not invent facts" in low
    assert "not yet specified" in low
    assert '"key_takeaway"' in p and '"on_screen_bullets"' in p
    assert "no code fences" in low


def test_prompt_does_not_list_forbidden_terms():
    p = opt().build_script_prompts(ADVISORY)
    text = (p["system_prompt"] + p["user_prompt"]).lower()
    for term in DEFAULT_SETTINGS["script_validation"]["forbidden_terms"]:
        assert term.lower() not in text, term


def test_prompt_uses_configured_limits():
    p = opt(max_bullets=2, max_hook_words=12).build_script_prompts(ADVISORY)["system_prompt"]
    assert "1 to 2 short strings" in p and "at most 12 words" in p


# --- select_hook_style ------------------------------------------------------


def test_hook_deterministic_and_case_insensitive():
    o = opt()
    first = o.select_hook_style("CVE-2026-1")
    assert all(o.select_hook_style("CVE-2026-1") == first for _ in range(5))
    assert o.select_hook_style(" cve-2026-1 ") == first
    assert opt().select_hook_style("CVE-2026-1") == first


def test_hook_rotation_covers_styles():
    o = opt()
    seen = {o.select_hook_style(f"CVE-2026-{i}") for i in range(60)}
    assert seen == {"question", "number", "scenario"}


def test_hook_config_driven_styles():
    o = opt(hook_styles=["number"])
    assert {o.select_hook_style(f"CVE-{i}") for i in range(20)} == {"number"}


def test_hook_rotation_off_first_style():
    o = opt(hook_rotation=False, hook_styles=["scenario", "question"])
    assert o.select_hook_style("CVE-1") == o.select_hook_style("CVE-2") == "scenario"


def test_hook_explicit_override_and_invalid_fallback():
    o = opt()
    assert o.select_hook_style("CVE-1", "Scenario ") == "scenario"
    assert o.select_hook_style("CVE-1", "bogus") == o.select_hook_style("CVE-1")
    assert o.select_hook_style("CVE-1", None) == o.select_hook_style("CVE-1", "")


def test_hook_invalid_config_styles_fall_back():
    assert opt(hook_styles=["nope", 5]).hook_styles == ["question", "number", "scenario"]
    assert opt(hook_styles=[]).hook_styles == ["question", "number", "scenario"]
    assert opt(hook_styles=["Question", "bad"]).hook_styles == ["question"]


def test_prompt_contains_selected_hook_text():
    p = opt().build_script_prompts(ADVISORY, hook_style="number")["system_prompt"]
    assert "CVSS score or severity" in p


@pytest.mark.parametrize("bad", ["x", None, [3]])
def test_invalid_numeric_config_uses_default(bad):
    o = opt(max_bullets=bad, max_bullet_chars=bad)
    assert o.max_bullets == 3 and o.max_bullet_chars == 48


def test_numeric_config_clamped():
    o = opt(max_bullets=99, max_bullet_chars=1)
    assert o.max_bullets == 5 and o.max_bullet_chars == 10


# --- normalize_scenes -------------------------------------------------------


def test_bullet_cap_three():
    out = normalize_scenes([sc(on_screen_bullets=list("abcdef"))], 3, opt())
    assert out[0]["on_screen_bullets"] == ["a", "b", "c"]


def test_non_string_bullets_dropped():
    out = normalize_scenes([sc(on_screen_bullets=[1, None, {"x": 1}, "ok", ["y"], ""])], 3, opt())
    assert out[0]["on_screen_bullets"] == ["ok"]


def test_bullet_length_and_word_caps():
    long = "word " * 50
    out = normalize_scenes([sc(on_screen_bullets=[long, "x" * 500])], 3, opt())
    for b in out[0]["on_screen_bullets"]:
        assert 0 < len(b) <= 48
    assert len(out[0]["on_screen_bullets"][0].split()) <= 8


def test_takeaway_cap():
    out = normalize_scenes([sc(key_takeaway="Long sentence. " * 100)], 3, opt())
    assert 0 < len(out[0]["key_takeaway"]) <= 160


def test_bare_string_bullet_wrapped():
    out = normalize_scenes([sc(on_screen_bullets="Apply the patch")], 3, opt())
    assert out[0]["on_screen_bullets"] == ["Apply the patch"]


def test_missing_keys_defaults():
    out = normalize_scenes([{"narration": "Patch now. Then verify."}], 3, opt())[0]
    assert out["title"] == "Scene 1"
    assert out["visual_cue"] == "Technical security slide"
    assert out["on_screen_bullets"] == []
    assert out["key_takeaway"] == "Patch now."


def test_legacy_three_key_scene():
    out = normalize_scenes([{"title": "A", "narration": "Hello there.", "visual_cue": "V"}], 3, opt())
    assert out[0]["title"] == "A" and out[0]["on_screen_bullets"] == []


def test_markdown_stripped_in_bullets():
    out = normalize_scenes([sc(on_screen_bullets=["**Patch** `now`"])], 3, opt())
    assert out[0]["on_screen_bullets"] == ["Patch now"]


def test_scene_count_cap_and_zero():
    assert len(normalize_scenes([sc()] * 5, 2, opt())) == 2
    assert normalize_scenes([sc()], 0, opt()) == []


@pytest.mark.parametrize(
    "garbage",
    [
        None,
        5,
        "str",
        {},
        [None, 1, "x", [], {}],
        [{"narration": 5}],
        [{"narration": "  "}],
        [{"narration": "ok", "key_takeaway": 7, "on_screen_bullets": 9, "title": [], "visual_cue": {}}],
        [{"narration": "ok", "on_screen_bullets": {"a": 1}}],
    ],
)
def test_garbage_never_raises(garbage):
    out = normalize_scenes(garbage, 3, opt())
    assert isinstance(out, list)
    for s in out:
        assert isinstance(s["on_screen_bullets"], list) and s["narration"]


def test_unicode_whitespace_tricks():
    tricky = ["​", "  ", "  a\t\nb  ", "‮"]
    out = normalize_scenes([sc(on_screen_bullets=tricky)], 3, opt())
    for b in out[0]["on_screen_bullets"]:
        assert b == b.strip() and "\n" not in b and "\t" not in b


def test_bullet_truncation_never_overflows_with_emoji():
    out = normalize_scenes([sc(on_screen_bullets=["\U0001f600" * 100])], 3, opt())
    assert len(out[0]["on_screen_bullets"][0]) <= 48


# --- validator integration --------------------------------------------------


def make_writer(responses, **val):
    s = settings()
    s["script_validation"].update(val)
    w = ScriptWriter(settings=s)
    calls, queue = [], list(responses)

    def fake(prompt, system_prompt=""):
        calls.append((prompt, system_prompt))
        return queue.pop(0) if queue else "not json"

    w.agent.query_local_agent = fake
    return w, calls


def payload(**kw):
    return json.dumps({"scenes": [sc(**kw)]})


@pytest.mark.parametrize(
    "field,value",
    [
        ("on_screen_bullets", ["Use this payload"]),
        ("key_takeaway", "Run the payload now."),
        ("on_screen_bullets", ["CVE-2020-0001"]),
        ("key_takeaway", "See CVE-2020-0001."),
        ("on_screen_bullets", ["CVSS 4.3"]),
        ("key_takeaway", "CVSS score of 5.5 overall."),
        ("on_screen_bullets", ["Critical severity"]),
    ],
)
def test_invented_content_in_extras_rejected(field, value):
    w, calls = make_writer([payload(**{field: value})] * 3, max_retries=0)
    with pytest.raises(ScriptValidationError):
        w.generate_episode_script(ADVISORY)


def test_extras_violation_retried_then_ok():
    w, calls = make_writer([payload(on_screen_bullets=["exploit payload"]), payload()], max_retries=1)
    out = w.generate_episode_script(ADVISORY)
    assert len(calls) == 2
    assert "payload" not in json.dumps(out["scenes"]).lower()


def test_invented_version_in_bullet_rejected():
    w, _ = make_writer([payload(on_screen_bullets=["Upgrade to 9.9.9"])] * 2, max_retries=0)
    with pytest.raises(ScriptValidationError):
        w.generate_episode_script(ADVISORY)


def test_term_past_word_cap_is_truncated_away():
    b = "one two three four five six seven eight payload"
    w, _ = make_writer([payload(on_screen_bullets=[b])], max_retries=0)
    out = w.generate_episode_script(ADVISORY)
    assert "payload" not in json.dumps(out["scenes"]).lower()


def test_v2_scene_keys_and_prompt_version():
    w, calls = make_writer([payload()])
    out = w.generate_episode_script(ADVISORY)
    assert out["prompt_version"] == PROMPT_VERSION == "v2"
    s = out["scenes"][0]
    assert set(s) == {"title", "narration", "key_takeaway", "on_screen_bullets", "visual_cue"}


def test_hook_style_override_reaches_prompt():
    w, calls = make_writer([payload()])
    w.generate_episode_script(ADVISORY, hook_style="scenario")
    assert "everyday scenario" in calls[0][1]


def test_validation_disabled_still_returns_prompt_version():
    w, _ = make_writer([payload()], enabled=False)
    assert w.generate_episode_script(ADVISORY)["prompt_version"] == "v2"


# --- fallback ---------------------------------------------------------------


def test_fallback_emits_new_keys_and_passes_validation():
    w, calls = make_writer(["garbage"] * 5, max_retries=1)
    out = w.generate_episode_script(ADVISORY, max_scenes=3)
    assert len(out["scenes"]) == 3
    for s in out["scenes"]:
        assert s["key_takeaway"] and 1 <= len(s["on_screen_bullets"]) <= 3
        assert all(len(b) <= 48 for b in s["on_screen_bullets"])
    assert w._validate(out["scenes"], ADVISORY, skip_text_rules=True) == []


# --- security review follow-ups ---------------------------------------------


def test_cf_chars_stripped_from_all_fields():
    raw = sc(
        title="Ti‮tle", narration="Hel​lo there.", key_takeaway="Pa​tch.", on_screen_bullets=["Bu‮llet"], visual_cue="V​C"
    )
    out = normalize_scenes([raw], 3, opt())[0]
    assert "‮" not in json.dumps(out, ensure_ascii=False)
    assert "​" not in json.dumps(out, ensure_ascii=False)
    assert out["on_screen_bullets"] == ["Bullet"]


def test_term_split_across_bullets_rejected():
    w, _ = make_writer([payload(on_screen_bullets=["reverse", "shell"])] * 2, max_retries=0)
    with pytest.raises(ScriptValidationError):
        w.generate_episode_script(ADVISORY)


def test_cve_id_split_across_bullets_rejected():
    w, _ = make_writer([payload(on_screen_bullets=["CVE-2024-", "1234"])] * 2, max_retries=0)
    with pytest.raises(ScriptValidationError):
        w.generate_episode_script(ADVISORY)


@pytest.mark.parametrize(
    "val,expected",
    [
        ("false", False),
        ("No", False),
        ("0", False),
        ("off", False),
        (False, False),
        ("true", True),
        ("on", True),
        (True, True),
        (None, True),
        ("weird", True),
    ],
)
def test_hook_rotation_bool_parsing(val, expected):
    assert opt(hook_rotation=val).hook_rotation is expected
