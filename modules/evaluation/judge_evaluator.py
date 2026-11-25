import ast
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from core.config_loader import get_harness_config
from modules.cyber_agent.base_harness import HarnessSpec
from modules.cyber_agent.sandbox_exec import SandboxExecutor

logger = logging.getLogger("AutoSec.JudgeEvaluator")


class JudgeEvaluator:
    """Objective judge for generated security code, based on sandboxed execution and quality metrics."""

    def __init__(
        self, scoring_set_path: str = "modules/evaluation/scoring_sets.json", settings: Optional[Dict[str, Any]] = None
    ):
        self.scoring_set_path = scoring_set_path
        self.settings = settings or {}
        self.pass_threshold: float = get_harness_config(self.settings)["pass_threshold"]
        self.sandbox = SandboxExecutor(settings=self.settings)

    def load_tasks(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.scoring_set_path):
            raise FileNotFoundError(f"Scoring set not found: {self.scoring_set_path}")
        with open(self.scoring_set_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload.get("tasks", [])

    @staticmethod
    def extract_python_code(raw_response: str) -> str:
        """استخراج كود Python النظيف من رد النموذج وإزالة علامات Markdown."""
        if not raw_response:
            return ""
        fenced = re.findall(r"```(?:python)?\s*(.*?)```", raw_response, flags=re.DOTALL | re.IGNORECASE)
        if fenced:
            return fenced[0].strip()
        return raw_response.strip()

    def _score_patterns(self, code: str, required: List[str], forbidden: List[str]) -> Dict[str, Any]:
        missing = [p for p in required if p not in code]
        found_forbidden = [p for p in forbidden if p in code]

        if found_forbidden:
            return {"score": 0.0, "missing": missing, "forbidden_found": found_forbidden}

        if not required:
            return {"score": 30.0, "missing": [], "forbidden_found": []}

        ratio = (len(required) - len(missing)) / len(required)
        return {
            "score": round(30.0 * ratio, 2),
            "missing": missing,
            "forbidden_found": [],
        }

    def _score_code_hygiene(self, code: str) -> Dict[str, Any]:
        """تقييم نظافة البنية البرمجية (Syntax صحيح، تعريف دالة، وجود توثيق أو فحص شرطي)."""
        points = 0.0
        notes: List[str] = []
        try:
            tree = ast.parse(code)
            points += 8.0
        except SyntaxError:
            return {"score": 0.0, "notes": ["Invalid Python syntax"]}

        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        if funcs:
            points += 6.0
            if any(ast.get_docstring(fn) for fn in funcs):
                points += 3.0
            else:
                notes.append("Missing function docstring")
        else:
            notes.append("No function definition found")

        has_guard = any(isinstance(n, (ast.If, ast.Try, ast.Raise)) for n in ast.walk(tree))
        if has_guard:
            points += 3.0
        else:
            notes.append("No explicit conditional/exception guard")

        return {"score": round(points, 2), "notes": notes}

    def evaluate_candidate(self, task: Dict[str, Any], raw_model_output: str) -> Dict[str, Any]:
        """تقييم مخرج واحد لمهمة محددة وإرجاع تقرير مفصل بالدرجات والملاحظات."""
        clean_code = self.extract_python_code(raw_model_output)
        if not clean_code:
            return {
                "task_id": task["task_id"],
                "passed": False,
                "total_score": 0.0,
                "breakdown": {"execution": 0.0, "security_patterns": 0.0, "hygiene": 0.0},
                "feedback": "Empty code returned by model.",
                "clean_code": "",
            }

        spec = HarnessSpec(
            task_id=task["task_id"],
            description=task.get("category", ""),
            target_code=clean_code,
            test_code=task.get("test_code", ""),
            timeout_sec=10,
            allowed_imports=task.get("allowed_imports", ["re", "json"]),
        )

        exec_result = self.sandbox.execute(spec)
        exec_score = 50.0 if exec_result["passed"] else 0.0

        pattern_res = self._score_patterns(
            clean_code,
            task.get("required_patterns", []),
            task.get("forbidden_patterns", []),
        )
        hygiene_res = self._score_code_hygiene(clean_code)

        total_score = round(exec_score + pattern_res["score"] + hygiene_res["score"], 2)
        feedback_items: List[str] = []
        if not exec_result["passed"]:
            feedback_items.append(f"Sandbox failed: {exec_result['stderr']} | Violations: {exec_result['violations']}")
        if pattern_res["missing"]:
            feedback_items.append(f"Missing required patterns: {pattern_res['missing']}")
        if pattern_res["forbidden_found"]:
            feedback_items.append(f"Forbidden patterns used: {pattern_res['forbidden_found']}")
        feedback_items.extend(hygiene_res["notes"])

        return {
            "task_id": task["task_id"],
            "category": task.get("category", ""),
            "passed": exec_result["passed"] and total_score >= self.pass_threshold,
            "total_score": total_score,
            "breakdown": {
                "execution": exec_score,
                "security_patterns": pattern_res["score"],
                "hygiene": hygiene_res["score"],
            },
            "execution": exec_result,
            "feedback": "; ".join(feedback_items) if feedback_items else "All checks passed cleanly.",
            "clean_code": clean_code,
        }


if __name__ == "__main__":
    judge = JudgeEvaluator()
    tasks = judge.load_tasks()
    sample_code = """
import os

def safe_join_path(base_dir: str, user_path: str) -> str:
    \"\"\"Resolve user_path safely inside base_dir.\"\"\"
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(base_abs, user_path))
    if os.path.commonpath([base_abs, target_abs]) != base_abs:
        raise ValueError("Path traversal detected")
    return target_abs
"""
    report = judge.evaluate_candidate(tasks[0], sample_code)
    print(json.dumps(report, indent=2, ensure_ascii=False))
