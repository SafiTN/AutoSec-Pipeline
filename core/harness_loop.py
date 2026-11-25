import logging
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.agent_runner import AgentRunner
from core.config_loader import get_harness_config, load_settings
from modules.evaluation.judge_evaluator import JudgeEvaluator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AutoSec.HarnessLoop")


class AutoHarnessLoop:
    """حلقة التطوير والتحقق الذاتي الحقيقية المعتمدة على AgentRunner و JudgeEvaluator."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        harness_cfg = get_harness_config(self.settings)
        ai_cfg = self.settings.get("ai", {})

        self.max_iterations: int = harness_cfg["max_iterations"]
        self.target_score: float = harness_cfg["target_score"]
        self.base_temperature: float = ai_cfg.get("temperature", 0.1)

        self.agent = AgentRunner(settings=self.settings)
        self.judge = JudgeEvaluator(settings=self.settings)

        self.system_prompt = (
            "You are a senior Python cybersecurity engineer. "
            "Return ONLY clean, self-contained, production-grade Python code inside a single ```python``` block. "
            "Include clear docstrings and strict input validation. Do not use forbidden modules or unsafe calls."
        )

    def _build_repair_prompt(self, original_prompt: str, previous_code: str, feedback: str) -> str:
        return (
            f"Original Task:\n{original_prompt}\n\n"
            f"Your previous implementation failed automated security & unit evaluation:\n"
            f"```python\n{previous_code}\n```\n\n"
            f"Evaluator Feedback:\n{feedback}\n\n"
            "Fix all issues strictly and return ONLY the corrected Python function inside a ```python``` block."
        )

    def _solve_single_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        task_id = task["task_id"]
        prompt = task["prompt"]
        best_report: Dict[str, Any] = {
            "task_id": task_id,
            "passed": False,
            "total_score": 0.0,
            "feedback": "No attempts executed.",
            "clean_code": "",
        }

        for attempt in range(1, self.max_iterations + 1):
            # خفض الحرارة تدريجياً عند التصحيح لزيادة الدقة
            self.agent.temperature = max(0.0, round(self.base_temperature - (attempt - 1) * 0.05, 2))
            logger.info("[%s] Attempt %d/%d (temp=%.2f)...", task_id, attempt, self.max_iterations, self.agent.temperature)

            raw_response = self.agent.query_local_agent(prompt=prompt, system_prompt=self.system_prompt)
            if raw_response.startswith("Error:"):
                logger.error("[%s] AgentRunner error: %s", task_id, raw_response)
                best_report["feedback"] = raw_response
                break

            report = self.judge.evaluate_candidate(task, raw_response)
            logger.info("[%s] Score: %.2f/100 | Passed: %s", task_id, report["total_score"], report["passed"])

            if report["total_score"] >= best_report["total_score"]:
                best_report = report

            if report["passed"] and report["total_score"] >= self.target_score:
                logger.info("[%s] Target achieved on attempt %d.", task_id, attempt)
                break

            prompt = self._build_repair_prompt(
                original_prompt=task["prompt"],
                previous_code=report.get("clean_code", ""),
                feedback=report.get("feedback", ""),
            )

        return best_report

    def run_optimization_loop(self) -> Dict[str, Any]:
        """تشغيل حلقة التقييم والتحسين على جميع مهام scoring_sets.json."""
        logger.info("[Auto-Harness] Starting real LLM evaluation & self-correction loop...")
        tasks = self.judge.load_tasks()
        if not tasks:
            raise RuntimeError("No tasks loaded from scoring_sets.json.")

        results: List[Dict[str, Any]] = []
        for task in tasks:
            res = self._solve_single_task(task)
            results.append(res)

        avg_score = round(sum(r["total_score"] for r in results) / len(results), 2)
        passed_count = sum(1 for r in results if r["passed"])
        pass_rate = round((passed_count / len(results)) * 100.0, 2)

        logger.info("[FINAL SUMMARY] Passed: %d/%d (%.1f%%) | Average Score: %.2f/100",
                    passed_count, len(results), pass_rate, avg_score)

        return {
            "temperature": self.agent.temperature,
            "average_score": avg_score,
            "pass_rate": pass_rate,
            "passed_count": passed_count,
            "total_tasks": len(results),
            "verified_artifacts": results,
        }


if __name__ == "__main__":
    loop = AutoHarnessLoop()
    summary = loop.run_optimization_loop()
    for item in summary["verified_artifacts"]:
        if item["task_id"] == "sec_path_traversal_01":
            print("\n--- sec_path_traversal_01 Feedback ---")
            print("Score:", item["total_score"], "| Passed:", item["passed"])
            print("Feedback:", item["feedback"])
            print("Code:\n" + item.get("clean_code", ""))
    print(f"\nPass Rate: {summary['pass_rate']}% | Average Score: {summary['average_score']}/100")
