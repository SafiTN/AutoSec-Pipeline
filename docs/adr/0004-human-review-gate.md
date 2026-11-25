# 0004. Human review gate for high-severity episodes

## Status
Accepted

## Context
T15: a script about a critical CVE (CVSS >= 9.0) must not be rendered until a human
approves it. This adds a second cross-run state file (after `covered_cves.json`, ADR 0001),
a CLI surface to `main.py`, and a new exit code. Gate point: in `run_pipeline` after
ScriptWriter/T06 validation and before `build_video`.

## Decision
1. **Hash-bound approval.** `script_sha256` = SHA-256 (hex) of
   `json.dumps({"selected_cve": selected_cve, "episode_script": episode_script}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
   encoded as UTF-8 (so the advisory facts are bound too). `--approve` recomputes it; mismatch is an
   error (exit 1). It also requires `episode_script.cve_id == selected_cve.cve_id` (else exit 1). Reviewer edits
   are not supported: to change a script, `--reject` and rerun. On approve the stored script is
   also re-run through the T06 validator against the stored advisory (defence in depth).
2. **Archive, never delete.** After approve/reject the file is renamed in the same dir to
   `pending_review.<approved|rejected>.<UTC YYYYMMDDTHHMMSSZ>[.N].json` with `status` updated
   (a `.N` counter is added on name collision; an existing archive is never overwritten).
   A failed approve (render error, tamper) leaves the file `pending` so it can be retried.
3. **`--reject` marks the CVE covered** (flat `covered_cves.json`, ADR 0001). Otherwise the
   highest-CVSS selection would re-pick it and re-gate forever.
4. **Pending file exists:** a normal run checks first (before harness, NVD, LLM), changes
   nothing, logs the file and the `--approve`/`--reject` commands, returns a result with
   `review_status: "pending"`, `output_video: None`; `__main__` exits 2. No manifest write.
5. **Sample runs (`is_sample`) skip the gate**; they are watermarked and never recorded.
6. **Pending schema** (`PendingReview` TypedDict): `schema_version: 1`, `status`
   (`pending|approved|rejected`), `reason` (`cvss>=threshold|severity|review_required|unknown_cvss`),
   `created_at`, `decided_at` (null until decided), `prompt_version`, `selected_cve` (dict),
   `episode_script` (dict), `script_sha256`. Unknown `schema_version` or missing key = corrupt (exit 1).
   Write via temp file + `os.replace` (atomic).
7. **CLI** (argparse in `__main__`): mutually exclusive `--approve`, `--reject`. Exit codes:
   0 = video produced, or reject succeeded; 1 = any error (missing/corrupt/tampered pending,
   nothing pending, render failure, usage error); 2 = pending review. argparse exits 2 on usage
   errors by default, which would collide: override `ArgumentParser.error` to exit 1.
8. **API:** `run_pipeline(run_harness=False, cve_limit=None, max_scenes=3, *, approve=False,
   reject=False)`. Existing callers and tests unchanged. Manifest gains `review_status`
   (`not_required|approved`) and, on approve, `approved_at`. Pending is never written to the manifest.

9. **Security notes (review of 2026-11-25).**
   - `script_sha256` is an integrity check against accidental edits, NOT authentication:
     anyone with write access to `output/` can edit the file and recompute the hash. Protecting
     `output/` is an operational responsibility.
   - Severity gate: besides CVSS, an advisory whose `severity` is `CRITICAL` or `UNKNOWN` is gated
     (reason `severity`) regardless of `fail_closed_on_unknown_cvss`. A warning is logged when
     `review.enabled` is false.
   - `--approve` also requires `selected_cve.cve_id` to match `^CVE-\d{4}-\d{4,}$` and rejects
     `is_sample: true` (exit 1).
   - Approve is not transactional. Order: render -> write manifest -> record covered CVE ->
     archive pending. A crash between steps can leave a manifest/covered entry with the file still
     pending; retrying `--approve` re-renders and is idempotent (covered file is a flat map).
     State files are written atomically (`_atomic_write_json`); archiving uses a single `os.replace`.

## Config
```yaml
review:
  enabled: true
  cvss_threshold: 9.0
  review_required: false            # true = gate every non-sample run
  fail_closed_on_unknown_cvss: true
paths:
  pending_review_filename: "pending_review.json"   # under paths.output_dir
```
Add the same defaults to `core/config_loader.py::DEFAULT_SETTINGS` plus one `review` accessor;
no other module reads these keys directly.

## Consequences
- Files: `main.py`, `config/settings.yaml`, `core/config_loader.py`, README, new tests
  (see T15 AC 8), CI dry-run workflow (exit 2 must not be reported as failure).
- A stuck pending file blocks all later runs by design; `--reject` is the escape hatch.
- Scheduled/CI runs never auto-approve.
- Two runs touching the pending file concurrently are out of scope (as ADR 0001).
