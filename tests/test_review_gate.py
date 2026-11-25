import json

import pytest

import main
from core.config_loader import DEFAULT_SETTINGS, get_review_config
from modules.content_pipeline.script_writer import ScriptWriter as RealWriter


def _cfg(**over):
    cfg = dict(DEFAULT_SETTINGS["review"])
    cfg.update(over)
    return cfg


@pytest.mark.parametrize(
    "score,expected",
    [(8.9, None), (9.0, "cvss>=threshold"), (9.1, "cvss>=threshold")],
)
def test_threshold_boundaries(score, expected):
    assert main.should_require_review({"cvss_score": score}, _cfg(), False) == expected


def test_review_required_disabled_sample_and_unknown():
    assert main.should_require_review({"cvss_score": 1.0}, _cfg(review_required=True), False) == "review_required"
    assert main.should_require_review({"cvss_score": 9.9}, _cfg(enabled=False), False) is None
    assert main.should_require_review({"cvss_score": 9.9}, _cfg(), True) is None
    assert main.should_require_review({"cvss_score": None}, _cfg(), False) == "unknown_cvss"
    assert main.should_require_review({"cvss_score": "high"}, _cfg(), False) == "unknown_cvss"
    assert main.should_require_review({"cvss_score": None}, _cfg(fail_closed_on_unknown_cvss=False), False) is None


def test_script_sha256_is_key_order_independent_and_sensitive():
    a = {"x": 1, "y": ["é"]}
    cve = {"cve_id": "CVE-2026-0001", "cvss_score": 9.8}
    assert main._review_sha256(cve, a) == main._review_sha256(cve, {"y": ["é"], "x": 1})
    assert main._review_sha256(cve, a) != main._review_sha256(cve, {"x": 2, "y": ["é"]})
    assert main._review_sha256(cve, a) != main._review_sha256({**cve, "cvss_score": 1.0}, a)


def _pending(tmp_path, script=None):
    settings = {"paths": {"output_dir": str(tmp_path), "pending_review_filename": "p.json"}}
    cve = {"cve_id": "CVE-2026-0001", "severity": "CRITICAL", "cvss_score": 9.8}
    script = script or {"cve_id": "CVE-2026-0001", "scenes": [], "prompt_version": "v"}
    return settings, main._write_pending_review(settings, cve, script, "cvss>=threshold")


def test_tampered_selected_cve_rejected_on_approve(tmp_path):
    settings, path = _pending(tmp_path)
    data = json.loads(open(path, encoding="utf-8").read())
    data["selected_cve"]["cvss_score"] = 1.0
    open(path, "w", encoding="utf-8").write(json.dumps(data))
    with pytest.raises(ValueError, match="sha256"):
        main._approve_pending(settings)


def test_cve_id_mismatch_rejected_on_approve(tmp_path):
    settings, _ = _pending(tmp_path, {"cve_id": "CVE-2026-9999", "scenes": [], "prompt_version": "v"})
    with pytest.raises(ValueError, match="inconsistent"):
        main._approve_pending(settings)


def test_archive_never_overwrites(tmp_path, monkeypatch):
    settings, path = _pending(tmp_path)
    pending = main._load_pending_review(settings)
    first = main._archive_pending_review(settings, pending, "rejected")
    main._atomic_write_json(path, dict(pending))
    fixed = main.datetime.fromisoformat(json.loads(open(first, encoding="utf-8").read())["decided_at"])
    monkeypatch.setattr(main, "datetime", type("D", (), {"now": staticmethod(lambda tz=None: fixed)}))
    second = main._archive_pending_review(settings, pending, "rejected")
    assert first != second
    assert json.loads(open(first, encoding="utf-8").read())["status"] == "rejected"


def test_review_config_validation():
    assert get_review_config({})["cvss_threshold"] == 9.0
    with pytest.raises(ValueError):
        get_review_config({"review": {"enabled": "yes"}})
    with pytest.raises(ValueError):
        get_review_config({"review": {"cvss_threshold": 11}})


def test_cli_usage_error_exits_1():
    with pytest.raises(SystemExit) as exc:
        main._cli(["--approve", "--reject"])
    assert exc.value.code == 1


def test_pending_roundtrip_and_tamper_detected(tmp_path, monkeypatch):
    settings = {"paths": {"output_dir": str(tmp_path), "pending_review_filename": "p.json"}}
    cve = {"cve_id": "CVE-2026-0001", "cvss_score": 9.8}
    script = {"scenes": [], "prompt_version": "v"}
    path = main._write_pending_review(settings, cve, script, "cvss>=threshold")
    assert main._load_pending_review(settings)["status"] == "pending"

    data = json.loads(open(path, encoding="utf-8").read())
    data["episode_script"]["scenes"] = [{"narration": "changed"}]
    open(path, "w", encoding="utf-8").write(json.dumps(data))
    with pytest.raises(ValueError, match="sha256"):
        main._approve_pending(settings)


# ---------- end-to-end gate flows (all collaborators mocked) ----------
CVE_ID = "CVE-2026-7777"


def _adv(score=9.8):
    severity = "CRITICAL" if score >= 9.0 else "HIGH"
    return {"cve_id": CVE_ID, "severity": severity, "cvss_score": score, "summary": "s", "is_sample": False}


def _script():
    return {
        "episode_title": "T",
        "cve_id": CVE_ID,
        "prompt_version": "pv1",
        "scenes": [{"title": "s", "narration": f"{CVE_ID} is critical. Patch it.", "visual_cue": "c"}],
    }


class _Calls:
    fetch = 0
    write = 0
    render = 0
    harness = 0


@pytest.fixture
def env(monkeypatch, tmp_path):
    calls = _Calls()
    state = {"score": 9.8, "render_ok": True, "render_raises": False}
    settings = {
        "nvd": {"max_results": 5},
        "script_validation": {"enabled": False},
        "paths": {
            "output_dir": str(tmp_path / "output"),
            "default_video_filename": "v.mp4",
            "manifest_filename": "m.json",
            "covered_cves_filename": "c.json",
            "pending_review_filename": "p.json",
        },
    }

    class Fetcher:
        def __init__(self, settings=None):
            pass

        def fetch_latest_cves(self, limit=3):
            calls.fetch += 1
            return [_adv(state["score"])]

    class Writer:
        _validation_view = staticmethod(RealWriter._validation_view)

        def __init__(self, settings=None):
            pass

        def generate_episode_script(self, advisory, max_scenes=3):
            calls.write += 1
            return _script()

    class Media:
        def __init__(self, settings=None):
            self.settings = settings

        def build_video(self, scenes, name, cve_id, severity, is_sample=False):
            calls.render += 1
            if state["render_raises"]:
                raise RuntimeError("boom")
            if not state["render_ok"]:
                return None
            out = tmp_path / "output" / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b"mp4")
            return str(out)

    class Harness:
        def __init__(self, *a, **k):
            calls.harness += 1

        def run(self, *a, **k):
            calls.harness += 1
            return {}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "NewsFetcher", Fetcher)
    monkeypatch.setattr(main, "ScriptWriter", Writer)
    monkeypatch.setattr(main, "CyberMediaGenerator", Media)
    monkeypatch.setattr(main, "AutoHarnessLoop", Harness)
    out = tmp_path / "output"
    return type(
        "E",
        (),
        dict(
            calls=calls,
            state=state,
            settings=settings,
            pending=out / "p.json",
            manifest=out / "m.json",
            covered=out / "c.json",
            out=out,
        ),
    )


def _trigger(env):
    return main.run_pipeline(run_harness=False, cve_limit=1, max_scenes=1)


def _archives(env, status):
    return list(env.out.glob(f"p.{status}.*.json"))


def test_gate_trigger_writes_pending_only(env):
    r = _trigger(env)
    assert r["review_status"] == "pending" and r["output_video"] is None
    assert env.pending.is_file()
    assert not env.manifest.exists() and not env.covered.exists()
    assert env.calls.render == 0
    assert json.loads(env.pending.read_text("utf-8"))["reason"] == "cvss>=threshold"


def test_below_threshold_renders_without_gate(env):
    env.state["score"] = 5.0
    r = _trigger(env)
    assert r["review_status"] == "not_required" and r["output_video"]
    assert not env.pending.exists() and CVE_ID in json.loads(env.covered.read_text("utf-8"))


def test_second_run_blocked_by_pending(env):
    _trigger(env)
    before = env.pending.read_bytes()
    fetches, writes = env.calls.fetch, env.calls.write
    r = main.run_pipeline(run_harness=True, cve_limit=1, max_scenes=1)
    assert r["review_status"] == "pending"
    assert env.pending.read_bytes() == before
    assert (env.calls.fetch, env.calls.write, env.calls.harness) == (fetches, writes, 0)
    assert not env.manifest.exists()


def test_approve_happy_path(env):
    _trigger(env)
    fetches, writes = env.calls.fetch, env.calls.write
    m = main.run_pipeline(approve=True)
    assert (env.calls.fetch, env.calls.write) == (fetches, writes)
    assert m["review_status"] == "approved" and m["approved_at"] and m["output_video"]
    disk = json.loads(env.manifest.read_text("utf-8"))
    assert disk["review_status"] == "approved" and disk["approved_at"]
    assert CVE_ID in json.loads(env.covered.read_text("utf-8"))
    assert not env.pending.exists() and len(_archives(env, "approved")) == 1
    assert json.loads(_archives(env, "approved")[0].read_text("utf-8"))["status"] == "approved"


def test_approve_failed_render_keeps_pending(env):
    _trigger(env)
    for mode in ("returns_none", "raises"):
        env.state["render_ok"] = mode != "returns_none"
        env.state["render_raises"] = mode == "raises"
        r = main.run_pipeline(approve=True)
        assert r["review_status"] == "pending" and r["render_error"]
        assert env.pending.is_file() and not env.manifest.exists() and not env.covered.exists()
        assert not _archives(env, "approved")
    assert main._cli(["--approve"]) == 1


def test_reject_covers_and_archives(env):
    _trigger(env)
    r = main.run_pipeline(reject=True)
    assert r["review_status"] == "rejected" and env.calls.render == 0
    assert CVE_ID in json.loads(env.covered.read_text("utf-8"))
    assert not env.pending.exists() and len(_archives(env, "rejected")) == 1
    assert not env.manifest.exists()


def test_approve_tamper_exits_1(env):
    _trigger(env)
    d = json.loads(env.pending.read_text("utf-8"))
    d["episode_script"]["scenes"][0]["narration"] = "evil"
    env.pending.write_text(json.dumps(d), "utf-8")
    assert main._cli(["--approve"]) == 1
    assert env.pending.is_file() and env.calls.render == 0 and not env.manifest.exists()


def test_cli_exit_codes(env):
    assert main._cli(["--approve"]) == 1  # nothing pending
    assert main._cli(["--reject"]) == 1
    assert main._cli([]) == 2  # gate triggered
    assert main._cli([]) == 2  # blocked by pending
    assert main._cli(["--reject"]) == 0
    env.covered.unlink()  # rejected CVE is filtered afterwards; reset to reuse the mock fetcher
    env.state["score"] = 5.0
    assert main._cli([]) == 0  # normal render
    env.covered.unlink()
    env.state["render_ok"] = False
    assert main._cli([]) == 1  # render failed


def test_approve_and_reject_together_raises(env):
    with pytest.raises(ValueError):
        main.run_pipeline(approve=True, reject=True)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("script_sha256"),
        lambda d: d.update(status="approved"),
        lambda d: d.update(schema_version=99),
        lambda d: d["selected_cve"].pop("cve_id"),
        lambda d: d.update(selected_cve=[]),
    ],
)
def test_corrupt_pending_rejected(env, mutate):
    _trigger(env)
    d = json.loads(env.pending.read_text("utf-8"))
    mutate(d)
    env.pending.write_text(json.dumps(d), "utf-8")
    with pytest.raises(ValueError):
        main.run_pipeline(approve=True)
    assert main._cli(["--reject"]) == 1


def test_non_json_pending_blocks_run(env):
    env.out.mkdir(parents=True)
    env.pending.write_text("{not json", "utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        main.run_pipeline()
    assert main._cli([]) == 1 and env.calls.fetch == 0


def test_approve_revalidation_failure_blocks_render(env):
    env.settings["script_validation"] = {"enabled": True, "forbidden_terms": ["patch it"]}
    _trigger(env)
    with pytest.raises(ValueError, match="re-validation"):
        main.run_pipeline(approve=True)
    assert env.calls.render == 0 and env.pending.is_file()


def test_atomic_write_cleans_tmp_on_failure(tmp_path):
    with pytest.raises(TypeError):
        main._atomic_write_json(str(tmp_path / "x.json"), {"a": object()})
    assert list(tmp_path.iterdir()) == []


def test_pending_filename_traversal_stripped(tmp_path):
    s = {"paths": {"output_dir": str(tmp_path), "pending_review_filename": "../../evil.json"}}
    assert main._pending_review_path(s) == str(tmp_path / "evil.json")


def test_nan_and_bool_cvss_are_unknown():
    assert main.should_require_review({"cvss_score": float("nan")}, _cfg(), False) == "unknown_cvss"
    assert main.should_require_review({"cvss_score": True}, _cfg(), False) == "unknown_cvss"


def test_severity_critical_or_unknown_gated_despite_fail_open():
    cfg = _cfg(fail_closed_on_unknown_cvss=False)
    assert main.should_require_review({"cvss_score": 5.0, "severity": "critical"}, cfg, False) == "severity"
    assert main.should_require_review({"cvss_score": 5.0, "severity": "UNKNOWN"}, cfg, False) == "severity"
    assert main.should_require_review({"cvss_score": 5.0, "severity": "HIGH"}, cfg, False) is None
    assert main.should_require_review({"cvss_score": 5.0, "severity": "CRITICAL"}, cfg, True) is None


def test_disabled_gate_logs_warning(caplog):
    with caplog.at_level("WARNING", logger="AutoSec.Main"):
        assert main.should_require_review({"cvss_score": 9.9}, _cfg(enabled=False), False) is None
    assert "DISABLED" in caplog.text


@pytest.mark.parametrize("bad", ["CVE-26-1", "cve-2026-0001", "CVE-2026-0001; rm", "../x"])
def test_approve_rejects_invalid_cve_id(tmp_path, bad):
    settings = {"paths": {"output_dir": str(tmp_path), "pending_review_filename": "p.json"}}
    main._write_pending_review(settings, {"cve_id": bad}, {"cve_id": bad, "scenes": []}, "severity")
    with pytest.raises(ValueError, match="invalid cve_id"):
        main._approve_pending(settings)


def test_approve_rejects_sample_advisory(tmp_path):
    settings = {"paths": {"output_dir": str(tmp_path), "pending_review_filename": "p.json"}}
    cve = {"cve_id": "CVE-2026-0001", "is_sample": True}
    main._write_pending_review(settings, cve, {"cve_id": "CVE-2026-0001", "scenes": []}, "severity")
    with pytest.raises(ValueError, match="sample"):
        main._approve_pending(settings)


def test_archive_moves_file_and_updates_status(tmp_path):
    settings, path = _pending(tmp_path)
    archived = main._archive_pending_review(settings, main._load_pending_review(settings), "approved")
    import os

    assert not os.path.exists(path)
    data = json.loads(open(archived, encoding="utf-8").read())
    assert data["status"] == "approved" and data["decided_at"]


def test_manifest_and_covered_written_atomically(tmp_path, monkeypatch):
    settings = {"paths": {"output_dir": str(tmp_path)}}
    calls = []
    real = main._atomic_write_json
    monkeypatch.setattr(main, "_atomic_write_json", lambda p, d: (calls.append(p), real(p, d))[1])
    main._write_manifest(settings, {"a": 1})
    main._record_covered_cve(settings, "CVE-2026-0001")
    assert len(calls) == 2
    assert "CVE-2026-0001" in json.loads(open(calls[1], encoding="utf-8").read())
