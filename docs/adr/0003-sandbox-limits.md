# 0003. Sandbox resource limits and no-network execution (best effort)

## Status
Accepted

## Context
T10. `modules/cyber_agent/sandbox_exec.py` runs LLM-generated Python in a subprocess
with only a wall-clock timeout, a hard-coded `.sandbox_runs` under `os.getcwd()`, and an
AST import check. There are no memory/output/process caps and no network isolation.
Code runs on a Windows laptop and on ubuntu CI.

## Decision
1. **Config** `sandbox:` in `config/settings.yaml` AND `DEFAULT_SETTINGS` (merged by
   `_deep_merge`, so partial YAML keeps defaults). Read once in `SandboxExecutor.__init__`
   via `settings.get("sandbox", {})`; no env vars, no literals in code.
   Keys: `timeout_sec` (default; `HarnessSpec.timeout_sec`, if set, wins but is clamped
   to this value as the hard maximum), `max_memory_mb`, `max_output_bytes` (stdout and
   stderr each; truncated, with a marker), `max_processes`, `work_root` (resolved with
   `resolve_project_path`, never `os.getcwd()`). Invalid/non-positive values fall back
   to defaults with a WARNING. `work_root` must resolve strictly inside `PROJECT_ROOT`
   (not the root itself), else default + WARNING; `cleanup()` verifies the run dir is
   inside `work_root` before `rmtree`. `allow_unlimited` (bool, default `false`, in
   YAML and `DEFAULT_SETTINGS`): see item 4.
2. **Security model: best effort, NOT a security boundary.** Layers are an accident
   guard for output from a 7B model; they do not stop a determined attacker. Do not run untrusted code
   from outside this pipeline. Layers: (a) static AST check (first filter only; bare `os` is no longer a default allowed
   import, only `os.path`; attributes of `os` other than `path`, `sys`/`modules`/`os`
   attributes, dunder escape identifiers, dangerous file/process names and string
   constants equal to them are rejected; `remove`/`replace` are rejected only as
   `os.*` attributes and name imports because they are common str/list methods);
   (b) child launched with `python -I`, minimal env (no tokens/proxy vars), cwd = per-run
   dir; (c) OS limits below; (d) timeout kills the whole process tree; (e) per-run dir
   always removed in `cleanup()`, also after timeout.
3. **POSIX**: `preexec_fn` calls `resource.setrlimit` for `RLIMIT_AS` (memory),
   `RLIMIT_NPROC` (`max_processes`), `RLIMIT_CPU` (= timeout), `RLIMIT_FSIZE`
   (= `max_output_bytes` x 4);
   `start_new_session=True` and `os.killpg` on timeout.
4. **Windows**: no `resource`. Create a Job Object via `ctypes` (kernel32) with
   `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `ACTIVE_PROCESS_LIMIT`, `KILL_ON_JOB_CLOSE`; assign
   the child before it runs: the process is created with `CREATE_SUSPENDED`, assigned
   to the job, then resumed with `NtResumeProcess` (no race window). If any ctypes call
   fails the child is killed and an error result is returned (`violations:
   ["SandboxLimitsUnavailable"]`), unless `sandbox.allow_unlimited: true`, in which case
   it logs a WARNING, resumes the child and runs with timeout plus output cap only.
   `_python_executable()` uses the base interpreter (`sys.base_prefix`) on a Windows
   venv, because the venv `python.exe` launcher spawns a child that a 1-process job
   would block; the sandbox therefore needs only the stdlib. `ctypes.windll` and `resource` imports
   are guarded inside platform-specific helpers so the module imports on both OSes.
   Isolate the helpers in a small class (`_apply_limits(proc)` / `_preexec`) for mocking.
5. **No network, layered**: (a) static check forbids `socket`, `urllib.request`,
   `http`, `requests`, `ftplib`, etc.; (b) env stripped of proxy vars; (c) optional
   runtime guard: the runner writes a small prelude into the run dir that is executed
   first (a wrapper script that patches then `runpy`s the target; `-I` ignores
   `PYTHONPATH`, so no sitecustomize) and replaces
   `socket.socket.connect/connect_ex/bind/sendto`, `socket.create_connection`,
   `getaddrinfo`, and `_socket.socket`/`getaddrinfo` with a function raising `OSError`.
   It is an accident guard only and bypassable by determined code, hence layer (a)
   stays. No OS firewall rules.
6. **Docker/containers: out of scope.** Would add a heavy dependency, break the
   laptop-runnable goal, and per CLAUDE.md rule 7 needs owner approval. Revisit as a
   separate task if the owner approves.
7. **Result dict unchanged**: `passed, stdout, stderr, exit_code, duration_sec,
   violations`. Limit hits appear as non-zero `exit_code` and a `stderr` note.

## Second-pass hardening
- Attribute names `__import__, getattr, setattr, delattr, builtins, codecs, importlib,
  sys, os` (plus `modules`) are banned on any object, and as string constants. Constant
  string concatenation (`"o"+"s"`) is folded before the string check. `os.path` stays
  allowed where `os.path` is in the import allowlist.
- Rejecting attribute access on all imported modules outside a safe set was not adopted:
  it breaks legitimate snippets (`re.compile`, `json.dumps`, ...) without a maintained
  per-module allowlist. **Residual bypass class**: a denylist cannot cover names built
  at runtime (`"".join([...])`, `chr()` sequences, `bytes.decode`, `str.format`) or
  other attribute chains reaching dangerous objects through allowed modules. This is
  why the sandbox is an accident guard, not a security boundary.
- Popen -> `limits.apply` window: wrapped in `try/except BaseException`; the child is
  killed and waited, then the exception re-raised (no leaked suspended process).
- Windows has no file-size limit (Job Objects lack an RLIMIT_FSIZE equivalent); disk
  fill is bounded only by the wall-clock timeout. POSIX uses RLIMIT_FSIZE.

## Consequences
- Limits on Windows are weaker (no CPU-time limit; wall-clock timeout only).
- POSIX `RLIMIT_NPROC` counts per user, so it is weak; the main fork guard is the
  static check (`subprocess`/`os.fork` forbidden). Windows ACTIVE_PROCESS_LIMIT is exact.
- Memory cap may break legitimate heavy snippets; tune `max_memory_mb`.
- Files: edit `modules/cyber_agent/sandbox_exec.py`, `core/config_loader.py`
  (`DEFAULT_SETTINGS["sandbox"]`; no new accessor needed, merge already exists),
  `config/settings.yaml`, `.gitignore` (`.sandbox_runs/` on its own line); new
  `tests/test_sandbox_exec.py` (tmp `work_root`, mock the limit helpers, short real
  subprocess only).
- Callers (unchanged signatures): `judge_evaluator.py` L9/L20, `harness_loop.py`.
- `work_root` default stays `.sandbox_runs`, now project-relative (was cwd-relative).
