"""T11: config-driven harness keys. All mocked: no network, no Ollama, no real sandbox."""
from unittest.mock import MagicMock

import pytest

from core.config_loader import get_harness_config
from core.harness_loop import AutoHarnessLoop
from modules.evaluation.judge_evaluator import JudgeEvaluator

CODE = (
    "```python\n"
    "def f(x):\n"
    '    """doc"""\n'
    "    if x:\n"
    "        return x\n"
    "    return 0\n"
    "```"
)
TASK = {"task_id": "t1", "prompt": "do it", "category": "c"}


def _h(**kw):
    return {"harness": kw}


# ---- get_harness_config ----

def test_defaults():
    for s in (None, {}, {"harness": None}):
        cfg = get_harness_config(s)
        assert cfg["max_iterations"] == 3
        assert cfg["target_score"] == 90.0
        assert cfg["pass_threshold"] == 80.0


def test_partial_override_merges_defaults():
    cfg = get_harness_config(_h(max_iterations=5))
    assert cfg["max_iterations"] == 5 and cfg["target_score"] == 90.0


@pytest.mark.parametrize("bad", [0, -1, True, False, 2.5, "3", None])
def test_bad_max_iterations(bad):
    with pytest.raises(ValueError):
        get_harness_config(_h(max_iterations=bad))


@pytest.mark.parametrize("key", ["pass_threshold", "target_score"])
@pytest.mark.parametrize(
    "bad", [True, "80", None, float("nan"), float("inf"), -float("inf")]
)
def test_non_number_scores(key, bad):
    with pytest.raises(ValueError):
        get_harness_config(_h(**{key: bad}))


def test_pass_threshold_above_target():
    with pytest.raises(ValueError):
        get_harness_config(_h(pass_threshold=95, target_score=90))


@pytest.mark.parametrize("pt,ts", [(-1, 90), (80, 101), (101, 101), (-5, -1)])
def test_out_of_range(pt, ts):
    with pytest.raises(ValueError):
        get_harness_config(_h(pass_threshold=pt, target_score=ts))


@pytest.mark.parametrize("pt,ts", [(90, 90), (0, 0), (100, 100), (0, 100), (79.5, 80)])
def test_boundaries_ok(pt, ts):
    cfg = get_harness_config(_h(pass_threshold=pt, target_score=ts))
    assert cfg["pass_threshold"] == pt and cfg["target_score"] == ts


# ---- harness loop ----

def _loop(max_iter, target, reports):
    settings = _h(max_iterations=max_iter, target_score=target, pass_threshold=0)
    loop = AutoHarnessLoop(settings=settings)
    loop.agent = MagicMock()
    loop.agent.query_local_agent.return_value = CODE
    loop.judge = MagicMock()
    loop.judge.evaluate_candidate.side_effect = list(reports)
    return loop


def _rep(score, passed):
    return {"task_id": "t1", "passed": passed, "total_score": score,
            "feedback": "fb", "clean_code": "x"}


def test_loop_reads_config():
    loop = AutoHarnessLoop(settings=_h(max_iterations=4, target_score=95, pass_threshold=70))
    assert loop.max_iterations == 4 and loop.target_score == 95


def test_loop_invalid_config_raises():
    with pytest.raises(ValueError):
        AutoHarnessLoop(settings=_h(max_iterations=0))


@pytest.mark.parametrize("n", [1, 2, 5])
def test_loop_runs_exactly_max_iterations_when_never_passing(n):
    loop = _loop(n, 90, [_rep(10, False)] * n)
    res = loop._solve_single_task(TASK)
    assert loop.agent.query_local_agent.call_count == n
    assert res["passed"] is False


def test_loop_stops_early_at_target():
    loop = _loop(5, 90, [_rep(50, False), _rep(90, True), _rep(100, True)])
    res = loop._solve_single_task(TASK)
    assert loop.agent.query_local_agent.call_count == 2
    assert res["total_score"] == 90 and res["passed"] is True


def test_loop_passed_below_target_keeps_going():
    loop = _loop(3, 95, [_rep(85, True)] * 3)
    loop._solve_single_task(TASK)
    assert loop.agent.query_local_agent.call_count == 3


def test_loop_agent_error_stops():
    loop = _loop(3, 90, [])
    loop.agent.query_local_agent.return_value = "Error: boom"
    res = loop._solve_single_task(TASK)
    assert loop.agent.query_local_agent.call_count == 1
    assert res["feedback"] == "Error: boom"


# ---- JudgeEvaluator ----

def _judge(settings):
    j = JudgeEvaluator(settings=settings)
    j.sandbox = MagicMock()
    j.sandbox.execute.return_value = {
        "passed": True, "stdout": "", "stderr": "", "violations": [], "exit_code": 0}
    return j


def test_judge_default_threshold_with_empty_settings():
    j = _judge({})
    assert j.pass_threshold == 80.0
    rep = j.evaluate_candidate(TASK, CODE)
    # exec 50 + patterns 30 + hygiene 20 = 100
    assert rep["total_score"] == 100.0 and rep["passed"] is True


def test_judge_threshold_changes_passed():
    weak = "x = 1"  # exec 50 + patterns 30 + syntax 8 = 88
    lenient = _judge(_h(pass_threshold=80, target_score=100))
    strict = _judge(_h(pass_threshold=95, target_score=100))
    assert lenient.evaluate_candidate(TASK, weak)["total_score"] == 88.0
    assert lenient.evaluate_candidate(TASK, weak)["passed"] is True
    assert strict.evaluate_candidate(TASK, weak)["passed"] is False


def test_judge_threshold_boundary():
    weak = "x = 1"
    probe = _judge({})
    score = probe.evaluate_candidate(TASK, weak)["total_score"]
    at = _judge(_h(pass_threshold=score, target_score=100))
    above = _judge(_h(pass_threshold=score + 1, target_score=100))
    assert at.evaluate_candidate(TASK, weak)["passed"] is True
    assert above.evaluate_candidate(TASK, weak)["passed"] is False


def test_judge_sandbox_failure_never_passes_even_threshold_zero():
    j = _judge(_h(pass_threshold=0, target_score=100))
    j.sandbox.execute.return_value = {
        "passed": False, "stdout": "", "stderr": "e", "violations": [], "exit_code": 1}
    assert j.evaluate_candidate(TASK, CODE)["passed"] is False


def test_judge_invalid_config_raises():
    with pytest.raises(ValueError):
        JudgeEvaluator(settings=_h(pass_threshold=95, target_score=90))
