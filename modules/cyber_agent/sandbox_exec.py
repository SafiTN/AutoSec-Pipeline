import ast
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

from modules.cyber_agent.base_harness import BaseHarness, HarnessSpec

logger = logging.getLogger("AutoSec.SandboxExec")

FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open"}
FORBIDDEN_MODULES = {"subprocess", "socket", "shutil", "ctypes", "pickle", "pty", "winreg"}


class SandboxExecutor(BaseHarness):
    """بيئة تنفيذ معزولة لفحص وتشغيل السكربتات المولدة بأمان."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        super().__init__(settings or {})
        self.work_dir: Optional[str] = None

    def static_security_check(self, code: str, allowed_imports: List[str]) -> List[str]:
        """فحص ثابت للكود لاكتشاف الاستيرادات أو الاستدعاءات الخطرة قبل التشغيل."""
        violations: List[str] = []
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return [f"SyntaxError: {exc}"]

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    is_allowed = (alias.name in allowed_imports) or (root_mod in allowed_imports)
                    if root_mod in FORBIDDEN_MODULES or root_mod not in allowed_imports:
                        violations.append(f"Forbidden import: {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                is_allowed = (alias.name in allowed_imports) or (root_mod in allowed_imports)
                if root_mod in FORBIDDEN_MODULES or root_mod not in allowed_imports:
                    violations.append(f"Forbidden from-import: {node.module}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                    violations.append(f"Forbidden call: {node.func.id}()")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen"}:
                    violations.append(f"Forbidden attribute call: {node.func.attr}()")

        return violations

    def prepare(self, spec: HarnessSpec) -> None:
        base_tmp = os.path.join(os.getcwd(), ".sandbox_runs")
        os.makedirs(base_tmp, exist_ok=True)
        self.work_dir = tempfile.mkdtemp(prefix=f"{spec.task_id}_", dir=base_tmp)

        script_path = os.path.join(self.work_dir, "candidate.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(spec.target_code)
            if spec.test_code:
                f.write("\n\n" + spec.test_code)

    def execute(self, spec: HarnessSpec) -> Dict[str, Any]:
        start_time = time.perf_counter()
        violations = self.static_security_check(spec.target_code, spec.allowed_imports)
        if spec.test_code:
            violations.extend(self.static_security_check(spec.test_code, spec.allowed_imports))

        if violations:
            logger.warning("[%s] Static check blocked execution: %s", spec.task_id, violations)
            return {
                "passed": False,
                "stdout": "",
                "stderr": "Blocked by static security policy.",
                "exit_code": -1,
                "duration_sec": round(time.perf_counter() - start_time, 4),
                "violations": violations,
            }

        try:
            self.prepare(spec)
            assert self.work_dir is not None
            script_path = os.path.join(self.work_dir, "candidate.py")

            # تشغيل الفرعي مع تعطيل تحميل ملفات المستخدم/المواقع قدر الإمكان
            env = {
                "PATH": os.environ.get("PATH", ""),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            proc = subprocess.run(
                [sys.executable, "-I", script_path],
                cwd=self.work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=spec.timeout_sec,
            )
            duration = round(time.perf_counter() - start_time, 4)
            passed = proc.returncode == 0
            return {
                "passed": passed,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "exit_code": proc.returncode,
                "duration_sec": duration,
                "violations": [],
            }
        except subprocess.TimeoutExpired:
            return {
                "passed": False,
                "stdout": "",
                "stderr": f"Execution timed out after {spec.timeout_sec}s.",
                "exit_code": 124,
                "duration_sec": round(time.perf_counter() - start_time, 4),
                "violations": ["TimeoutExpired"],
            }
        except Exception as exc:
            logger.exception("[%s] Sandbox execution error", spec.task_id)
            return {
                "passed": False,
                "stdout": "",
                "stderr": f"Fallback error: {exc}",
                "exit_code": 1,
                "duration_sec": round(time.perf_counter() - start_time, 4),
                "violations": [f"RuntimeException: {type(exc).__name__}"],
            }
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        if self.work_dir and os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir, ignore_errors=True)
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