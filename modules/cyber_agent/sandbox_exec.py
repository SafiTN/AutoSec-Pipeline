"""Best-effort sandbox for running LLM-generated Python snippets.

SECURITY MODEL (see docs/adr/0003-sandbox-limits.md): the layers below are an
accident guard for output from a small local model. They are NOT a security
boundary and must never be used to run untrusted code from outside this pipeline.
"""

import ast
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config_loader import DEFAULT_SETTINGS, PROJECT_ROOT, resolve_project_path
from modules.cyber_agent.base_harness import BaseHarness, HarnessSpec

logger = logging.getLogger("AutoSec.SandboxExec")

FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
}
# Dotted entries match the module itself and any submodule.
FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "shutil",
    "ctypes",
    "pickle",
    "pty",
    "winreg",
    "urllib.request",
    "http",
    "requests",
    "ftplib",
    "smtplib",
    "telnetlib",
    "socketserver",
    "xmlrpc",
    "ssl",
    "multiprocessing",
    "asyncio",
}
# Names that must not be imported from any module, used as attributes, or appear
# as string constants.
FORBIDDEN_NAMES = {
    "system",
    "popen",
    "fork",
    "forkpty",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "startfile",
    "open",
    "fdopen",
    "unlink",
    "rmdir",
    "rename",
    "kill",
    "posix_spawn",
    "posix_spawnp",
    "scandir",
    "listdir",
    "walk",
    "environ",
    "chdir",
    "mkdir",
    "makedirs",
}
# Too common as str/list methods and string values (str.replace, list.remove,
# errors="replace") to ban as plain attributes/constants. They are still rejected
# when imported by name and as attributes of the `os` name (see static check).
AMBIGUOUS_OS_NAMES = {"remove", "replace"}
FORBIDDEN_IDENTIFIERS = {
    "__builtins__",
    "__subclasses__",
    "__globals__",
    "__dict__",
    "__class__",
    "__bases__",
    "__mro__",
    "__code__",
    "__closure__",
    "__loader__",
    "__spec__",
}
# Attribute names that reach other modules through an allowed one (os.sys.modules).
FORBIDDEN_ATTRS_ANY = {
    "sys",
    "modules",
    "os",
    "builtins",
    "codecs",
    "importlib",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
}
# "http" as a string is a legitimate URL scheme value, so it is exempt from the
# string-constant check (the module itself stays forbidden).
_STRING_EXEMPT = {"http"}

_CREATE_SUSPENDED = 0x00000004  # Windows process creation flag
_FSIZE_MULTIPLE = 4  # RLIMIT_FSIZE = max_output_bytes * this

# Runner executed instead of the candidate. Runtime socket block is an accident
# guard only (trivially bypassable); the static check stays the first layer.
_RUNNER_SOURCE = """import runpy, socket, sys, _socket

def _blocked(*args, **kwargs):
    raise OSError("network access is disabled in the sandbox")

for _name in ("connect", "connect_ex", "bind", "sendto"):
    setattr(socket.socket, _name, _blocked)
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
_socket.socket = _blocked
_socket.getaddrinfo = _blocked
runpy.run_path(sys.argv[1], run_name="__main__")
"""


def _module_matches(name: str, entries) -> bool:
    """True if `name` equals an entry or is a submodule of it."""
    return any(name == e or name.startswith(e + ".") for e in entries)


def _is_forbidden_module(name: str) -> bool:
    return _module_matches(name, FORBIDDEN_MODULES)


def _is_allowed_module(name: str, allowed_imports: List[str]) -> bool:
    root = name.split(".")[0]
    return root in allowed_imports or _module_matches(name, allowed_imports)


def _inside_project(work_root: str) -> bool:
    """True if work_root resolves strictly inside PROJECT_ROOT."""
    try:
        resolved = Path(resolve_project_path(work_root)).resolve()
        return Path(PROJECT_ROOT).resolve() in resolved.parents
    except (OSError, ValueError):
        return False


def _is_inside(path: str, root: Path) -> bool:
    try:
        return root.resolve() in Path(path).resolve().parents
    except (OSError, ValueError):
        return False


def _python_executable() -> str:
    """Interpreter for the child. On Windows a venv python.exe is a launcher that
    spawns the real interpreter as a child, which a 1-process Job Object blocks;
    use the base interpreter directly (the sandbox only needs the stdlib)."""
    if os.name == "nt" and sys.prefix != sys.base_prefix:
        base = os.path.join(sys.base_prefix, "python.exe")
        if os.path.isfile(base):
            return base
    return sys.executable


def _is_forbidden_attr(name: str) -> bool:
    return name in FORBIDDEN_NAMES


def _is_forbidden_string(value: str) -> bool:
    if value in _STRING_EXEMPT:
        return False
    return (
        value in FORBIDDEN_NAMES
        or value in FORBIDDEN_CALLS
        or value in FORBIDDEN_IDENTIFIERS
        or value in FORBIDDEN_ATTRS_ANY
        or _is_forbidden_module(value)
    )


def _fold_str(node: ast.AST) -> Optional[str]:
    """Fold constant string concatenation (recursive BinOp Add of str constants)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left), _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


class _OSLimits:
    """Platform-specific resource limits; isolated so tests can mock it."""

    def __init__(self, max_memory_mb: int, max_processes: int, cpu_seconds: int, max_file_bytes: Optional[int] = None):
        self.max_memory_mb = max_memory_mb
        self.max_processes = max_processes
        self.cpu_seconds = cpu_seconds
        self.max_file_bytes = max_file_bytes
        self._job: Any = None

    # ---- POSIX ----
    def preexec(self) -> None:
        """Runs in the child before exec (POSIX only)."""
        import resource  # guarded: not available on Windows

        mem = self.max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
        fsize = self.max_file_bytes if self.max_file_bytes else mem
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        try:
            nproc = self.max_processes
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
        except (ValueError, OSError):
            pass

    @property
    def popen_kwargs(self) -> Dict[str, Any]:
        if os.name == "nt":
            # Started suspended: the Job Object is attached before any code runs.
            return {"creationflags": _CREATE_SUSPENDED}
        return {"preexec_fn": self.preexec, "start_new_session": True}

    # ---- Windows ----
    def apply(self, proc: "subprocess.Popen") -> Optional[str]:
        """Attach the suspended child to a Job Object, then resume it (Windows).

        Never raises. Returns None on success (or on POSIX) or an error message;
        the caller decides whether to kill the child or continue unlimited.
        """
        if os.name != "nt":
            return None
        try:
            self._apply_job(proc)
        except Exception as exc:  # ctypes failures must not break the run
            logger.warning("OS limits unavailable: %s", exc)
            return f"OS limits unavailable: {exc}"
        try:
            self.resume(proc)
        except Exception as exc:
            logger.warning("Could not resume sandbox child: %s", exc)
            return f"Could not resume child: {exc}"
        return None

    def resume(self, proc: "subprocess.Popen") -> None:
        """Resume a process created with CREATE_SUSPENDED (Windows)."""
        import ctypes
        from ctypes import wintypes

        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        status = ntdll.NtResumeProcess(int(proc._handle))  # noqa: SLF001
        if status != 0:
            raise OSError(f"NtResumeProcess failed (status {status:#x})")

    def _apply_job(self, proc: "subprocess.Popen") -> None:
        import ctypes
        from ctypes import wintypes

        class BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IOC(ctypes.Structure):
            _fields_ = [
                (n, ctypes.c_uint64)
                for n in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")
            ]

        class EXT(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC),
                ("IoInfo", IOC),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        job = k32.CreateJobObjectW(None, None)
        if not job:
            raise OSError(f"CreateJobObjectW failed ({ctypes.get_last_error()})")
        info = EXT()
        info.BasicLimitInformation.LimitFlags = 0x8 | 0x100 | 0x2000
        info.BasicLimitInformation.ActiveProcessLimit = self.max_processes
        info.ProcessMemoryLimit = self.max_memory_mb * 1024 * 1024
        if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            k32.CloseHandle(job)
            raise OSError(f"SetInformationJobObject failed ({err})")
        if not k32.AssignProcessToJobObject(job, int(proc._handle)):  # noqa: SLF001
            err = ctypes.get_last_error()
            k32.CloseHandle(job)
            raise OSError(f"AssignProcessToJobObject failed ({err})")
        self._job = (k32, job)

    def kill(self, proc: "subprocess.Popen") -> None:
        """Kill the child and its descendants."""
        try:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                self.release()  # KILL_ON_JOB_CLOSE ends the whole job
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.kill()
        except OSError:
            pass

    def release(self) -> None:
        if self._job:
            k32, job = self._job
            self._job = None
            try:
                k32.CloseHandle(job)
            except Exception:  # pragma: no cover - best effort
                pass


class SandboxExecutor(BaseHarness):
    """Best-effort isolated runner for generated scripts (NOT a security boundary)."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        super().__init__(settings or {})
        self.work_dir: Optional[str] = None
        self._work_root: Optional[Path] = None
        self.cfg = self._load_config(self.settings.get("sandbox", {}))

    @staticmethod
    def _load_config(raw: Any) -> Dict[str, Any]:
        defaults = DEFAULT_SETTINGS["sandbox"]
        raw = raw if isinstance(raw, dict) else {}
        cfg: Dict[str, Any] = {}
        for key in ("timeout_sec", "max_memory_mb", "max_output_bytes", "max_processes"):
            value = raw.get(key, defaults[key])
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                logger.warning("Invalid sandbox.%s=%r; using default %r", key, value, defaults[key])
                value = defaults[key]
            cfg[key] = value
        work_root = raw.get("work_root", defaults["work_root"])
        if not isinstance(work_root, str) or not work_root.strip():
            logger.warning("Invalid sandbox.work_root=%r; using default", work_root)
            work_root = defaults["work_root"]
        elif not _inside_project(work_root):
            logger.warning(
                "sandbox.work_root=%r must resolve inside the project and not be the project root; using default",
                work_root,
            )
            work_root = defaults["work_root"]
        cfg["work_root"] = work_root
        allow = raw.get("allow_unlimited", defaults["allow_unlimited"])
        if not isinstance(allow, bool):
            logger.warning("Invalid sandbox.allow_unlimited=%r; using default", allow)
            allow = defaults["allow_unlimited"]
        cfg["allow_unlimited"] = allow
        return cfg

    def static_security_check(self, code: str, allowed_imports: List[str]) -> List[str]:
        """Best-effort static scan for dangerous imports/calls before running.

        First filter only; it can be bypassed and is not a security boundary.
        """
        violations: List[str] = []
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return [f"SyntaxError: {exc}"]

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_forbidden_module(alias.name) or not _is_allowed_module(alias.name, allowed_imports):
                        violations.append(f"Forbidden import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0 or not node.module:
                    violations.append("Forbidden relative import")
                    continue
                if _is_forbidden_module(node.module) or not _is_allowed_module(node.module, allowed_imports):
                    violations.append(f"Forbidden from-import: {node.module}")
                for alias in node.names:
                    if alias.name == "*":
                        violations.append(f"Forbidden star import: {node.module}")
                    elif _is_forbidden_module(f"{node.module}.{alias.name}"):
                        violations.append(f"Forbidden from-import: {node.module}.{alias.name}")
                    elif (
                        _is_forbidden_attr(alias.name)
                        or alias.name in FORBIDDEN_CALLS
                        or alias.name in FORBIDDEN_IDENTIFIERS
                        or alias.name in AMBIGUOUS_OS_NAMES
                        or alias.name in FORBIDDEN_ATTRS_ANY
                    ):
                        violations.append(f"Forbidden name import: {alias.name}")
            elif isinstance(node, ast.Constant):
                if isinstance(node.value, str) and _is_forbidden_string(node.value):
                    violations.append(f"Forbidden string constant: {node.value!r}")
            elif isinstance(node, ast.BinOp):
                folded = _fold_str(node)
                if folded is not None and _is_forbidden_string(folded):
                    violations.append(f"Forbidden string constant: {folded!r}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and (
                    node.func.id in FORBIDDEN_CALLS or _is_forbidden_attr(node.func.id)
                ):
                    violations.append(f"Forbidden call: {node.func.id}()")
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_IDENTIFIERS:
                violations.append(f"Forbidden name: {node.id}")
            elif isinstance(node, ast.Attribute):
                attr = node.attr
                if attr in FORBIDDEN_IDENTIFIERS or attr in FORBIDDEN_ATTRS_ANY or _is_forbidden_attr(attr):
                    violations.append(f"Forbidden attribute: {attr}")
                elif isinstance(node.value, ast.Name) and node.value.id == "os" and attr != "path":
                    violations.append(f"Forbidden os attribute: {attr}")

        return violations

    def prepare(self, spec: HarnessSpec) -> None:
        base_tmp = Path(resolve_project_path(self.cfg["work_root"]))
        base_tmp.mkdir(parents=True, exist_ok=True)
        self._work_root = base_tmp
        self.work_dir = tempfile.mkdtemp(prefix=f"{spec.task_id}_", dir=str(base_tmp))

        script_path = os.path.join(self.work_dir, "candidate.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(spec.target_code)
            if spec.test_code:
                f.write("\n\n" + spec.test_code)
        with open(os.path.join(self.work_dir, "runner.py"), "w", encoding="utf-8") as f:
            f.write(_RUNNER_SOURCE)

    def _minimal_env(self) -> Dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if os.name == "nt" and os.environ.get("SYSTEMROOT"):
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]  # required by Python on Windows
        return env

    def _read_capped(self, path: str) -> str:
        limit = int(self.cfg["max_output_bytes"])
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                data = f.read(limit)
        except OSError:
            return ""
        text = data.decode("utf-8", errors="replace").strip()
        if size > limit:
            text += f"\n[truncated: output exceeded {limit} bytes]"
        return text

    def _result(self, start: float, **kw: Any) -> Dict[str, Any]:
        base = {
            "passed": False,
            "stdout": "",
            "stderr": "",
            "exit_code": 1,
            "duration_sec": round(time.perf_counter() - start, 4),
            "violations": [],
        }
        base.update(kw)
        return base

    def execute(self, spec: HarnessSpec) -> Dict[str, Any]:
        start_time = time.perf_counter()
        violations = self.static_security_check(spec.target_code, spec.allowed_imports)
        if spec.test_code:
            violations.extend(self.static_security_check(spec.test_code, spec.allowed_imports))

        if violations:
            logger.warning("[%s] Static check blocked execution: %s", spec.task_id, violations)
            return self._result(
                start_time,
                stderr="Blocked by static security policy.",
                exit_code=-1,
                violations=violations,
            )

        timeout = min(float(spec.timeout_sec), float(self.cfg["timeout_sec"]))
        limits = _OSLimits(
            int(self.cfg["max_memory_mb"]),
            int(self.cfg["max_processes"]),
            int(timeout) + 1,
            max_file_bytes=int(self.cfg["max_output_bytes"]) * _FSIZE_MULTIPLE,
        )
        try:
            self.prepare(spec)
            assert self.work_dir is not None
            out_path = os.path.join(self.work_dir, "stdout.txt")
            err_path = os.path.join(self.work_dir, "stderr.txt")

            with open(out_path, "wb") as out_f, open(err_path, "wb") as err_f:
                proc = subprocess.Popen(
                    [_python_executable(), "-I", "runner.py", "candidate.py"],
                    cwd=self.work_dir,
                    env=self._minimal_env(),
                    stdin=subprocess.DEVNULL,
                    stdout=out_f,
                    stderr=err_f,
                    **limits.popen_kwargs,
                )
                try:
                    limit_error = limits.apply(proc)
                except BaseException:
                    # Interrupted between Popen and limits: never leak the child.
                    limits.kill(proc)
                    proc.wait()
                    limits.release()
                    raise
                if limit_error:
                    if not self.cfg["allow_unlimited"]:
                        limits.kill(proc)
                        proc.wait()
                        limits.release()
                        logger.error("[%s] %s; refusing to run unlimited", spec.task_id, limit_error)
                        return self._result(
                            start_time,
                            stderr=f"Sandbox limits could not be applied: {limit_error}",
                            violations=["SandboxLimitsUnavailable"],
                        )
                    logger.warning(
                        "[%s] Running WITHOUT OS limits (sandbox.allow_unlimited=true): %s", spec.task_id, limit_error
                    )
                    try:
                        limits.resume(proc)
                    except Exception as exc:  # already running, or resume impossible
                        logger.debug("resume after limit failure: %s", exc)
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    limits.kill(proc)
                    proc.wait()
                    return self._result(
                        start_time,
                        stderr=f"Execution timed out after {timeout}s.",
                        exit_code=124,
                        violations=["TimeoutExpired"],
                    )
                finally:
                    limits.release()

            return self._result(
                start_time,
                passed=proc.returncode == 0,
                stdout=self._read_capped(out_path),
                stderr=self._read_capped(err_path),
                exit_code=proc.returncode,
            )
        except Exception as exc:
            logger.exception("[%s] Sandbox execution error", spec.task_id)
            return self._result(
                start_time,
                stderr=f"Fallback error: {exc}",
                violations=[f"RuntimeException: {type(exc).__name__}"],
            )
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        if self.work_dir and os.path.exists(self.work_dir):
            if self._work_root is not None and _is_inside(self.work_dir, self._work_root):
                shutil.rmtree(self.work_dir, ignore_errors=True)
            else:
                logger.error("Refusing to remove %r: not inside the sandbox work_root", self.work_dir)
        self.work_dir = None


if __name__ == "__main__":
    sample_spec = HarnessSpec(
        task_id="test_url_norm",
        description="Validate URL parsing helper",
        target_code="from urllib.parse import urlparse\ndef is_https(u): return urlparse(u).scheme == 'https'",
        test_code="assert is_https('https://example.com') is True\nprint('OK')",
    )
    executor = SandboxExecutor()
    print(executor.execute(sample_spec))
