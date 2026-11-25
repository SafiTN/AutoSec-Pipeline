"""Tests for modules/cyber_agent/sandbox_exec.py (T10). Real subprocesses only for tiny safe snippets."""
import importlib
import logging
import os
import sys
from pathlib import Path

import pytest

from modules.cyber_agent import sandbox_exec
from modules.cyber_agent.base_harness import HarnessSpec
from modules.cyber_agent.sandbox_exec import SandboxExecutor

REPO_ROOT = Path(__file__).resolve().parent.parent
IMPORTS = ["math", "re", "json", "urllib.parse"]


@pytest.fixture(autouse=True)
def project_root_is_tmp(tmp_path, monkeypatch):
    """work_root must live inside PROJECT_ROOT; point both at tmp_path for tests."""
    monkeypatch.setattr(sandbox_exec, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(
        sandbox_exec, "resolve_project_path", lambda p: (tmp_path / p).resolve())


def make_executor(tmp_path, **overrides):
    cfg = {
        "timeout_sec": 10,
        "max_memory_mb": 256,
        "max_output_bytes": 65536,
        "max_processes": 1,
        "work_root": str(tmp_path / "runs"),
    }
    cfg.update(overrides)
    return SandboxExecutor({"sandbox": cfg})


def spec(code, test="", timeout=10, imports=None, task="t"):
    return HarnessSpec(
        task_id=task, description="d", target_code=code, test_code=test,
        timeout_sec=timeout, allowed_imports=imports if imports is not None else list(IMPORTS),
    )


@pytest.fixture
def ex(tmp_path):
    return make_executor(tmp_path)


def check(ex, code, imports=None):
    return ex.static_security_check(code, imports if imports is not None else list(IMPORTS))


# ---------- second-pass hardening ----------
def test_codecs_builtins_bypass_rejected(ex):
    code = ('import json; b = json.codecs.builtins; m = b.__import__("o"+"s"); '
            'b.getattr(m, "s"+"ystem")("x")')
    assert check(ex, code, ["json"])


@pytest.mark.parametrize("code", [
    "x = a.__import__('z')", "x = a.getattr(b, 'c')", "a.setattr(b, 'c', 1)",
    "a.delattr(b, 'c')", "x = a.builtins", "x = a.codecs", "x = a.importlib",
    "x = a.sys", "x = a.os",
])
def test_banned_attribute_names(ex, code):
    assert check(ex, code)


@pytest.mark.parametrize("code", [
    "x = 'o' + 's'", "x = 'sy' + 'st' + 'em'", "x = ('__imp' + 'ort__')",
    "x = 'sub' + 'process'",
])
def test_constant_concat_folded(ex, code):
    assert any("Forbidden string constant" in v for v in check(ex, code))


def test_legit_snippets_still_pass(ex):
    code = (
        "import os.path, re, json\n"
        "p = os.path.join('a', 'b')\n"
        "s = 'ab' + 'cd'\n"
        "r = re.compile('x').sub('y', s.replace('a', 'b'))\n"
        "print(json.dumps({'p': p, 'r': r}))\n"
    )
    assert check(ex, code, ["os.path", "re", "json"]) == []


def test_apply_interrupt_kills_child(ex, monkeypatch):
    killed = []

    class FakeProc:
        pid = 1
        def wait(self, timeout=None): return 0
        def kill(self): killed.append("proc")

    class FakeLimits:
        popen_kwargs = {}
        def __init__(self, *a, **k): pass
        def apply(self, proc): raise KeyboardInterrupt
        def kill(self, proc): killed.append("limits")
        def release(self): killed.append("release")

    monkeypatch.setattr(sandbox_exec, "_OSLimits", FakeLimits)
    monkeypatch.setattr(sandbox_exec.subprocess, "Popen", lambda *a, **k: FakeProc())
    with pytest.raises(KeyboardInterrupt):
        ex.execute(spec("x = 1"))
    assert "limits" in killed and "release" in killed


# ---------- static check ----------
def test_from_import_allowed(ex):
    assert check(ex, "from urllib.parse import urlparse\nurlparse('x')") == []


def test_from_import_forbidden_module(ex):
    v = check(ex, "from subprocess import run", imports=["subprocess"])
    assert v and "subprocess" in v[0]


def test_from_import_not_in_allowlist(ex):
    assert check(ex, "from collections import OrderedDict")


def test_from_forbidden_submodule_via_name(ex):
    assert check(ex, "from urllib import request", imports=["urllib"])


def test_star_import_rejected(ex):
    v = check(ex, "from math import *")
    assert any("star" in x.lower() for x in v)


def test_star_import_forbidden_module(ex):
    assert check(ex, "from socket import *", imports=["socket"])


def test_import_dotted_allowed_and_forbidden(ex):
    assert check(ex, "import urllib.parse") == []
    assert check(ex, "import urllib.request", imports=["urllib"])
    assert check(ex, "import a.b")


def test_relative_import_rejected(ex):
    assert any("relative" in x.lower() for x in check(ex, "from . import x"))
    assert any("relative" in x.lower() for x in check(ex, "from .m import x"))


def test_from_os_import_system_rejected(ex):
    assert check(ex, "from os import system\nsystem('echo hi')")


def test_aliased_os_system_rejected(ex):
    v = check(ex, "import os as o\no.system('echo hi')")
    assert any("system" in x for x in v)


@pytest.mark.parametrize("code", [
    "getattr(1, 'x')", "globals()", "locals()", "vars()", "eval('1')", "exec('1')",
    "open('f')", "__import__('os')", "x = __builtins__", "().__class__.__subclasses__()",
])
def test_dangerous_builtins_rejected(ex, code):
    assert check(ex, code)


@pytest.mark.parametrize("mod", ["socket", "requests", "http.client", "ssl", "asyncio", "urllib.request"])
def test_network_modules_forbidden_even_if_allowed(ex, mod):
    assert check(ex, f"import {mod}", imports=[mod, mod.split(".")[0]])


def test_syntax_error_reported(ex):
    assert check(ex, "def (")[0].startswith("SyntaxError")


def test_execute_blocks_on_violation_without_running(ex, tmp_path):
    r = ex.execute(spec("import socket", imports=["socket"]))
    assert r["passed"] is False and r["exit_code"] == -1 and r["violations"]
    assert not (tmp_path / "runs").exists()  # nothing prepared


# ---------- real execution ----------
def test_plain_passing_run(ex):
    """Windows concern: max_processes=1 Job Object must not break the venv launcher."""
    r = ex.execute(spec("def f(): return 2", "assert f() == 2\nprint('OK')"))
    assert r["passed"] is True, r
    assert r["exit_code"] == 0
    assert "OK" in r["stdout"]


def test_result_keys_unchanged(ex):
    r = ex.execute(spec("x = 1"))
    assert set(r) == {"passed", "stdout", "stderr", "exit_code", "duration_sec", "violations"}
    blocked = ex.execute(spec("import socket", imports=["socket"]))
    assert set(blocked) == set(r)


def test_failing_run_nonzero(ex):
    r = ex.execute(spec("raise SystemExit(3)"))
    assert r["passed"] is False and r["exit_code"] == 3


def test_runtime_socket_block_in_real_child(tmp_path):
    """Allow socket in allowlist bypassing static check by patching it; child must still fail to connect."""
    exe = make_executor(tmp_path)
    exe.static_security_check = lambda code, allowed: []
    r = exe.execute(spec(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e)\n"
    ))
    assert "BLOCKED" in r["stdout"] and "disabled in the sandbox" in r["stdout"], r


def test_env_is_minimal_and_proxy_free(ex, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://x")
    monkeypatch.setenv("SECRET_TOKEN", "s3cr3t")
    env = ex._minimal_env()
    assert "HTTP_PROXY" not in env and "SECRET_TOKEN" not in env


def test_secret_env_not_visible_to_child(ex, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "s3cr3t")
    r = ex.execute(spec("import os.path\nprint('x')", imports=["os.path"]))
    assert r["passed"]
    assert "SECRET_TOKEN" not in ex._minimal_env()


def test_timeout_kills_and_cleans_up(tmp_path):
    ex = make_executor(tmp_path)
    r = ex.execute(spec("while True:\n    pass", timeout=1))
    assert r["passed"] is False and r["exit_code"] == 124
    assert r["violations"] == ["TimeoutExpired"]
    assert r["duration_sec"] < 8
    assert ex.work_dir is None
    runs = tmp_path / "runs"
    assert not runs.exists() or list(runs.iterdir()) == []


def test_timeout_clamped_to_config(tmp_path):
    ex = make_executor(tmp_path, timeout_sec=1)
    r = ex.execute(spec("while True:\n    pass", timeout=60))
    assert r["exit_code"] == 124
    assert r["duration_sec"] < 8
    assert "1.0s" in r["stderr"]


def test_output_truncation(tmp_path):
    ex = make_executor(tmp_path, max_output_bytes=100)
    r = ex.execute(spec("print('A' * 5000)"))
    assert r["passed"] is True
    assert "[truncated" in r["stdout"]
    assert r["stdout"].count("A") == 100


def test_cleanup_after_success_and_no_repo_leftovers(ex, tmp_path):
    ex.execute(spec("x = 1"))
    assert ex.work_dir is None
    runs = tmp_path / "runs"
    assert list(runs.iterdir()) == []
    assert not (REPO_ROOT / ".sandbox_runs").exists()


def test_cleanup_idempotent(ex):
    ex.cleanup()
    ex.cleanup()
    assert ex.work_dir is None


# ---------- config ----------
def test_invalid_config_falls_back_with_warning(tmp_path, caplog):
    bad = {"sandbox": {"timeout_sec": -1, "max_memory_mb": "lots", "max_output_bytes": True,
                       "max_processes": 0, "work_root": ""}}
    with caplog.at_level(logging.WARNING, logger="AutoSec.SandboxExec"):
        ex = SandboxExecutor(bad)
    from core.config_loader import DEFAULT_SETTINGS
    assert ex.cfg == DEFAULT_SETTINGS["sandbox"]
    assert len(caplog.records) >= 5


def test_non_dict_sandbox_section_uses_defaults():
    from core.config_loader import DEFAULT_SETTINGS
    assert SandboxExecutor({"sandbox": "nope"}).cfg == DEFAULT_SETTINGS["sandbox"]
    assert SandboxExecutor().cfg == DEFAULT_SETTINGS["sandbox"]


def test_settings_yaml_has_sandbox_section():
    from core.config_loader import load_settings
    s = load_settings()["sandbox"]
    assert set(s) >= {"timeout_sec", "max_memory_mb", "max_output_bytes", "max_processes",
                      "work_root", "allow_unlimited"}
    assert s["allow_unlimited"] is False


def test_work_root_relative_resolves_via_project_root(monkeypatch, tmp_path):
    ex = SandboxExecutor({"sandbox": {"work_root": "wr"}})
    r = ex.execute(spec("x = 1"))
    assert r["passed"] and (tmp_path / "wr").is_dir()


# ---------- import safety ----------
def test_module_imports_without_resource_and_ctypes(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)
    monkeypatch.setitem(sys.modules, "ctypes", None)
    mod = importlib.reload(sandbox_exec)
    try:
        assert hasattr(mod, "SandboxExecutor")
    finally:
        monkeypatch.undo()
        importlib.reload(sandbox_exec)


def test_apply_never_raises_when_ctypes_fails(monkeypatch):
    lim = sandbox_exec._OSLimits(64, 1, 5)
    monkeypatch.setattr(sandbox_exec.os, "name", "nt")
    monkeypatch.setattr(lim, "_apply_job", lambda p: (_ for _ in ()).throw(OSError("boom")))
    err = lim.apply(object())  # must not raise
    assert "boom" in err
    assert lim._job is None


def test_popen_kwargs_per_platform(monkeypatch):
    lim = sandbox_exec._OSLimits(64, 1, 5)
    monkeypatch.setattr(sandbox_exec.os, "name", "nt")
    assert lim.popen_kwargs == {"creationflags": sandbox_exec._CREATE_SUSPENDED}
    monkeypatch.setattr(sandbox_exec.os, "name", "posix")
    assert lim.popen_kwargs["start_new_session"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX rlimits only")
def test_posix_memory_limit_enforced(tmp_path):
    ex = make_executor(tmp_path, max_memory_mb=64)
    r = ex.execute(spec("x = bytearray(512 * 1024 * 1024)"))
    assert r["passed"] is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group kill")
def test_posix_timeout_kills_process_group(tmp_path):
    ex = make_executor(tmp_path)
    r = ex.execute(spec("import math\nwhile True:\n    pass", timeout=1))
    assert r["exit_code"] == 124


# ---------- security review findings ----------
@pytest.mark.parametrize("code", [
    "import os.path\nos.sys.modules['subprocess']",
    "import os.path\nos.path.sys.modules",
    "import os.path\nos.remove('x')",
    "import os.path\nos.open('x', 0)",
    "import os.path\nos.environ",
    "import os.path\nos.listdir('.')",
    "import os.path\nos.replace('a', 'b')",
    "import os.path\nos.kill(1, 9)",
    "import os.path\nos.makedirs('d')",
    "import os\nos.getcwd()",
    "from os import remove",
    "from os import path",
    "f = lambda: 0\nf.__globals__",
    "f = lambda: 0\nf.__code__",
    "x = ().__class__.__bases__",
    "x = (1).__class__.__mro__",
    "x = {}.__dict__",
    "x = {'__globals__': 1}",
    "d = {}\nd['__builtins__']",
    "x = 'system'",
    "x = 'subprocess'",
    "x = 'environ'",
    "x = 'open'",
    "x = '__subclasses__'",
])
def test_review_bypasses_rejected(ex, code):
    assert check(ex, code, imports=["os.path", "math"])


@pytest.mark.parametrize("code", [
    "x = 'a-b'.replace('-', '_')",
    "x = [1]\nx.remove(1)",
    "x = b'a'.decode('utf-8', errors='replace')",
    "x = 'http'",
    "import os.path\nx = os.path.abspath('.')",
])
def test_review_legit_code_still_allowed(ex, code):
    assert check(ex, code, imports=["os.path"]) == []


def test_bare_os_not_in_defaults():
    import json
    assert "os" not in HarnessSpec(task_id="t", description="d", target_code="").allowed_imports
    sets = json.loads((REPO_ROOT / "modules/evaluation/scoring_sets.json").read_text(encoding="utf-8"))
    for task in sets["tasks"]:
        assert "os" not in task["allowed_imports"]
    judge_src = (REPO_ROOT / "modules/evaluation/judge_evaluator.py").read_text(encoding="utf-8")
    assert '["os"' not in judge_src.split("allowed_imports=task.get(")[1].split(")")[0]


def test_scoring_set_path_traversal_test_passes_static_check(ex):
    import json
    sets = json.loads((REPO_ROOT / "modules/evaluation/scoring_sets.json").read_text(encoding="utf-8"))
    task = sets["tasks"][0]
    assert check(ex, task["test_code"], imports=task["allowed_imports"]) == []


# ---------- allow_unlimited / Windows limit failure ----------
class _FakeProc:
    def __init__(self):
        self.killed = False
        self.returncode = 0
        self.pid = 1

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0


def _fail_apply(monkeypatch, proc):
    monkeypatch.setattr(sandbox_exec.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(
        sandbox_exec._OSLimits, "apply", lambda self, p: "OS limits unavailable: boom")
    monkeypatch.setattr(sandbox_exec._OSLimits, "kill", lambda self, p: p.kill())
    monkeypatch.setattr(sandbox_exec._OSLimits, "resume", lambda self, p: None)


def test_limit_failure_kills_and_errors_by_default(tmp_path, monkeypatch):
    proc = _FakeProc()
    _fail_apply(monkeypatch, proc)
    ex = make_executor(tmp_path)
    r = ex.execute(spec("x = 1"))
    assert proc.killed is True
    assert r["passed"] is False and r["violations"] == ["SandboxLimitsUnavailable"]
    assert set(r) == {"passed", "stdout", "stderr", "exit_code", "duration_sec", "violations"}
    assert ex.work_dir is None


def test_allow_unlimited_continues_with_warning(tmp_path, monkeypatch, caplog):
    proc = _FakeProc()
    _fail_apply(monkeypatch, proc)
    ex = make_executor(tmp_path, allow_unlimited=True)
    with caplog.at_level(logging.WARNING, logger="AutoSec.SandboxExec"):
        r = ex.execute(spec("x = 1"))
    assert proc.killed is False and r["passed"] is True
    assert any("WITHOUT OS limits" in rec.message for rec in caplog.records)


def test_allow_unlimited_must_be_bool(tmp_path):
    assert make_executor(tmp_path, allow_unlimited="yes").cfg["allow_unlimited"] is False


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object")
def test_windows_job_limits_applied_before_resume(ex):
    r = ex.execute(spec("print('OK')"))
    assert r["passed"] is True and "OK" in r["stdout"]


# ---------- work_root validation / cleanup ----------
@pytest.mark.parametrize("bad", ["..", "../outside", ".", "/"])
def test_work_root_outside_or_equal_project_root_rejected(tmp_path, caplog, bad):
    from core.config_loader import DEFAULT_SETTINGS
    with caplog.at_level(logging.WARNING, logger="AutoSec.SandboxExec"):
        ex = make_executor(tmp_path, work_root=bad)
    assert ex.cfg["work_root"] == DEFAULT_SETTINGS["sandbox"]["work_root"]
    assert any("work_root" in r.message for r in caplog.records)


def test_work_root_inside_project_accepted(tmp_path):
    assert make_executor(tmp_path, work_root="sub/dir").cfg["work_root"] == "sub/dir"


def test_cleanup_refuses_dir_outside_work_root(tmp_path, caplog):
    ex = make_executor(tmp_path)
    ex._work_root = tmp_path / "runs"
    victim = tmp_path / "victim"
    victim.mkdir()
    ex.work_dir = str(victim)
    with caplog.at_level(logging.ERROR, logger="AutoSec.SandboxExec"):
        ex.cleanup()
    assert victim.exists() and ex.work_dir is None


def test_fsize_limit_uses_output_cap(tmp_path, monkeypatch):
    seen = {}
    real = sandbox_exec._OSLimits

    class Spy(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            seen["fsize"] = self.max_file_bytes

    monkeypatch.setattr(sandbox_exec, "_OSLimits", Spy)
    make_executor(tmp_path, max_output_bytes=1000).execute(spec("x = 1"))
    assert seen["fsize"] == 1000 * sandbox_exec._FSIZE_MULTIPLE


def test_runtime_guard_patches_bind_sendto_and_underscore_socket(tmp_path):
    exe = make_executor(tmp_path)
    exe.static_security_check = lambda code, allowed: []
    r = exe.execute(spec(
        "import socket, _socket\n"
        "s = socket.socket.__new__(socket.socket)\n"
        "for name in ('bind', 'sendto'):\n"
        "    try:\n"
        "        getattr(s, name)(('127.0.0.1', 0))\n"
        "    except OSError:\n"
        "        print('BLOCKED', name)\n"
        "try:\n"
        "    _socket.socket()\n"
        "except OSError:\n"
        "    print('BLOCKED _socket')\n"
    ))
    assert "BLOCKED bind" in r["stdout"] and "BLOCKED sendto" in r["stdout"], r
    assert "BLOCKED _socket" in r["stdout"], r
