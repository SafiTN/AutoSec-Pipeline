# 0002. Script fact-check validator with retry-then-fail-loudly

## Status
Accepted

## Context
T06. `ScriptWriter.generate_episode_script` makes one Ollama call and sanitizes the
result; any parse failure silently becomes `_build_fallback_scenes`. Nothing checks
CVE id, severity, CVSS, versions or forbidden terms (CLAUDE.md rules 2 and 3).
Advisories always have a numeric `cvss_score` (ADR 0001 invariant). Sample advisories
use ids like `CVE-2025-29927-SAMPLE`, so a naive id compare would flag the advisory's
own id; the validator compares the extracted `CVE-\d{4}-\d{4,}` token against the same
token extracted from `advisory["cve_id"]`.

## Decision
1. **Config** (`script_validation`, in `config/settings.yaml` AND `DEFAULT_SETTINGS`;
   merged by `_deep_merge`, so a partial YAML section keeps defaults). Read only via
   `settings.get("script_validation", {})` inside `ScriptWriter.__init__`; no env vars.
   `max_retries` = EXTRA attempts (total = 1 + max_retries); clamp negatives to 0.
   `forbidden_terms` defaults: payload, exploit code, shellcode, reverse shell,
   proof of concept, poc, step-by-step exploit, weaponiz.
2. **Pure validator** `modules/content_pipeline/script_validator.py`:
   `validate_script(scenes, advisory, rules) -> List[str]`; `rules` is the config
   dict. No I/O, no logging of scene text. Scans `title`, `narration`, `visual_cue`.
   Also defines `class ScriptValidationError(ValueError)` (message: violations +
   attempt count, no scene text).
3. **Normalization**: `unicodedata.normalize("NFKC", s).casefold()` then collapse
   whitespace runs to one space, applied to scene text, advisory text and terms before
   any match. Terms match with `(?<!\w)term(?!\w)` except stems ending in `iz`
   (`weaponiz`), matched as prefix `(?<!\w)weaponiz`. Escape terms with `re.escape`.
   Regexes must be linear: no nested quantifiers; bounded gaps (`.{0,20}`/`\s{0,5}`).
4. **Rules** (violation strings name rule + offending token, e.g. "CVE id CVE-2024-1111
   does not match advisory"): (a) CVE id; (b) severity claims (`<L> severity`,
   `severity (of|is|:) <L>`, `rated <L>`); UNKNOWN advisory severity forbids any claim;
   (c) `cvss` followed within 20 chars by a decimal, compared as float; (d) version
   tokens `(?<![\w.])v?\d+\.\d+(?:\.\d+)*(?![\w.])` must be a substring of the
   normalized advisory text (`summary` plus `affected_versions`/`fixed_versions`
   if present) or equal the CVSS score; (e) forbidden terms.
5. **Retry loop in `ScriptWriter`** (signature and return shape unchanged). Private
   helpers: `_attempt(prompts, feedback) -> Optional[List[scene]]` (query, parse,
   sanitize) and `_validate(scenes, advisory)`. For attempt in `range(1+max_retries)`:
   query; unparseable -> record "unparseable", continue; parsed -> validate; empty ->
   return. On violations, log WARNING (rule names/counts only) and call
   `PromptOptimizer.build_retry_feedback(violations) -> str` (new, prompt-engineer owns
   wording; restates "advisory facts only, defensive only", lists the rule and the
   WRONG value class but never echoes forbidden terms or payload text), appended to
   `user_prompt`. Feedback is rebuilt from the latest violations, not accumulated.
6. **Outcomes**: any attempt validated -> return it. At least one parsed-but-invalid
   and none valid -> raise `ScriptValidationError`; NO fallback, no manifest. ALL
   attempts unparseable -> deterministic fallback (warn). Fallback is checked with
   rules (a)-(c) only; failure there raises `ScriptValidationError` (code bug guard).
   It is exempt from (d)/(e) because NVD summaries may contain such words.
7. **`enabled: false`**: skip validation and retries (single attempt, today's
   behaviour including fallback), log one WARNING "fact-checking disabled".
8. **main.py**: no signature change; `run_pipeline` does not catch the error, so it
   propagates before manifest/covered-CVE writes. `__main__` message becomes
   `print(f"\n[ERROR] Pipeline aborted: {exc}")`.

## Consequences
- Validation failure is now a hard exit 1 (was silent fallback); heuristics can
  false-positive (e.g. "Windows 10.0"); mitigation: `enabled`, conservative regexes.
- Worst case Ollama calls per run: 1 + max_retries (default 3) at 120 s each.
- Files: new `modules/content_pipeline/script_validator.py`; edit `script_writer.py`,
  `core/prompt_optimizer.py` (new method), `core/config_loader.py`,
  `config/settings.yaml`, `main.py` (`__main__` print only); new tests
  `tests/test_script_validator.py`, `tests/test_script_writer_factcheck.py`.
- Existing tests that mock a single Ollama response with sample-like text must
  be re-checked (they now run the validator); grep tests for `generate_episode_script`
  and `ScriptWriter` and update mocks that invent versions or CVE ids.
- Callers of `generate_episode_script`: `main.py:227` only.

## Note: limits of the forbidden-term check
The forbidden-term check is a keyword heuristic, not a guarantee. It tolerates
plurals and separators (`-`, `_`, spaces) and flags words mixing Latin with
Cyrillic/Greek letters, but fully non-Latin spellings, paraphrases or other
obfuscation can still pass. It reduces risk; it does not replace human review.
Non-boolean `enabled` values fail safe (validation stays on); a non-integer
`max_retries` falls back to the default (2).
