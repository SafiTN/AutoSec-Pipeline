# 0001. Covered-CVE state file for repeat-avoidance in CVE selection

## Status
Accepted

## Context
T05 needs `_select_primary_advisory` to avoid re-picking a CVE already published in
a prior run. This is the pipeline's **first cross-run persistent state file** — every
other output (manifest, video) is overwritten per run. It also needs a bigger
candidate pool (today capped at `nvd.default_limit`=3) and an explicit "no CVSS data"
sentinel, since `0.0` is ambiguous with a real score. Confirmed against the current
code: `resolve_project_path(relative_or_abs: str) -> Path` takes one path-like string
and resolves it against `PROJECT_ROOT`; it does not know about `paths.output_dir`
itself, so callers must join `output_dir` + filename first, e.g.
`resolve_project_path(os.path.join(settings["paths"]["output_dir"], settings["paths"]["covered_cves_filename"]))`.
This matches the project-manager's draft exactly — no change needed there.

## Decision
1. **Pool size**: `run_pipeline` sources its `None`-default fetch limit from
   `nvd.max_results` (10) instead of `nvd.default_limit` (3). Explicit `cve_limit`
   still wins. `nvd.default_limit` is unchanged/kept (still `NewsFetcher`'s own
   internal default).
2. **CVSS sentinel**: `NewsFetcher._extract_cvss_info` returns
   `{"cvss_score": None, "severity": "UNKNOWN"}` on no match (was `0.0`). Advisories
   are now `Optional[float]` on `cvss_score`. Confirmed safe: `script_writer.py`
   and `core/prompt_optimizer.py` only read `cvss_score` via `.get(..., "N/A")`,
   which does **not** catch a present `None` value (it would render the literal
   string `"None"` in narration/prompts) — but `_select_primary_advisory` always
   filters `cvss_score is None` out *before* an advisory reaches `ScriptWriter`, and
   `FALLBACK_ADVISORIES` entries carry real numeric scores, so no `None` can reach
   those code paths today. This is a load-bearing invariant: **never pass a raw,
   unfiltered advisory into `ScriptWriter`** — keep selection as the only gate.
3. **Selection**: `_select_primary_advisory(advisories, covered_cve_ids: Optional[Set[str]] = None) -> Dict[str, Any]`.
   Filters `cvss_score is None`, then `cve_id in covered_cve_ids`, then
   `max(..., key=cvss_score)`. Raises `ValueError` distinguishing: empty input /
   all missing CVSS / all covered. Backward compatible (new optional param).
4. **Schema and path**: flat JSON dict, `{"<cve_id>": "<UTC ISO-8601>"}`. Membership
   check is a plain `in` on keys; timestamp is informational (future pruning), no
   migration needed if fields are added later since it's keyed by id, not a list
   index. New key `paths.covered_cves_filename: "covered_cves.json"` in both
   `config/settings.yaml` and `core/config_loader.py::DEFAULT_SETTINGS["paths"]`.
   Path = `resolve_project_path(os.path.join(paths.output_dir, paths.covered_cves_filename))`.
5. **Read**: missing file -> empty set. Parse failure -> **also includes** valid
   JSON that isn't an object (e.g. a list/string), not just `JSONDecodeError` —
   mirror `config_loader.load_settings`'s `isinstance(loaded, dict)` check. Both
   cases: log WARNING, return empty set, never raise. `_load_covered_cve_ids`
   returns `Set[str]` (the dict's keys); timestamps aren't needed for membership.
6. **Write**: only after manifest is written AND `generated_video is not None` AND
   `selected_cve.get("is_sample")` is `False`. Re-read current file (same
   corrupt-tolerant logic), upsert, write with `indent=2, ensure_ascii=False`.
7. **Out of scope**: concurrent/parallel runs writing this file simultaneously.
   Single-operator, single-run-at-a-time local pipeline per CLAUDE.md. No file
   locking or atomic rename; consistent with the manifest write, which has the
   same property today. Do not build retry/locking on top of this assumption
   without revisiting this ADR.

## Consequences
- `main.py` needs `from typing import Set` added; `_select_primary_advisory` call
  site gains a second argument; two new small helpers (`_load_covered_cve_ids`,
  `_record_covered_cve`).
- Existing test `tests/test_news_fetcher_fallback.py::test_advisory_without_cvss_defaults_gracefully`
  asserts `cvss_score == 0.0` at line 267 — **must be updated to `is None`** as
  part of this change (this specific test wasn't named in the backlog's "known
  test impact" note; flagging it here so it isn't missed).
- `tests/test_main_nvd_default_limit.py` default-limit assertion changes per
  backlog point 1 (already called out there).
- A no-CVSS or all-covered pool now hard-fails (`ValueError`, uncaught, same
  pattern as `NvdFetchError`) rather than silently degrading — intentional per
  CLAUDE.md rule 1/3, but operators must know to widen `lookback_days`/`max_results`
  or prune `covered_cves.json` when this happens.
