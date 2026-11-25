# AutoSec-Pipeline — Team Charter

Local-first pipeline: NVD CVE advisory -> English script (Ollama) -> Edge-TTS voiceover -> Pillow slides -> MoviePy MP4 -> `output/last_episode_manifest.json`.
Owner speaks Arabic: **write all replies, reports and status updates to the owner in Arabic**; code, comments, commit messages, prompts and docs stay in English.

## Architecture (read before changing anything)
- `main.py` — orchestrator (`run_pipeline`).
- `core/` — `config_loader.py`, `agent_runner.py` (Ollama), `prompt_optimizer.py`, `harness_loop.py`.
- `modules/content_pipeline/` — `news_fetcher.py`, `script_writer.py`, `media_generator.py`.
- `modules/cyber_agent/` + `modules/evaluation/` — sandbox, judge, scoring sets.
- `config/settings.yaml` — the single source of configuration. **Code must read it; no hard-coded URLs, models, timeouts or paths.**
- `tests/`, `.github/workflows/auto_pipeline.yml`.

## Commands
```
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -v          # must stay green
python main.py               # needs Ollama running + internet
```

## Team and workflow
Subagents live in `.claude/agents/`. Subagents cannot call each other, so **the main session is the orchestrator** and follows this loop for every task in `docs/BACKLOG.md`:

1. `project-manager` — refines the task, acceptance criteria, order, risks.
2. `architect` — only if the task changes structure, config schema or interfaces (writes a short ADR in `docs/adr/`).
3. Implementer — `pipeline-developer`, `prompt-engineer` or `media-developer`, on a branch `task/<ID>-<slug>`.
4. `qa-engineer` — adds/updates tests, runs the full suite.
5. `security-reviewer` — reviews the diff (mandatory for fetcher, prompts, sandbox, anything touching secrets or published content).
6. `devops-engineer` — CI/deps/scheduling tasks, and final CI check.
7. `project-manager` — verifies acceptance criteria, updates the backlog status, reports to the owner (Arabic).

Never skip steps 4 and 5. Never merge with failing tests.

## Definition of done
- Acceptance criteria in the backlog item are met.
- `python -m pytest -v` passes; new behaviour has tests (network and Ollama mocked, no live calls in tests).
- No new hard-coded config values; README/docs updated if behaviour changed.
- Security review has no open High findings.
- Small, focused commits with clear messages.

## Non-negotiable rules
1. **Never publish or render content about a fake or unverified CVE.** If NVD is unreachable, stop with a clear error unless `allow_fallback: true` is set explicitly.
2. **Defensive content only:** no exploit code, payloads or step-by-step attack instructions in scripts, slides or prompts.
3. **No invented facts:** CVE id, severity, CVSS, affected versions and fixed versions in a script must come from the advisory data. Unknown means say "not yet specified".
4. **No secrets in the repo** (`.env` stays ignored); never log tokens.
5. Do not change the public signatures used by `main.py` without updating every caller and test.
6. Respect YouTube policies: avoid repetitive/templated mass output; keep AI-content disclosure in mind.
7. Ask the owner (in Arabic) before: adding paid services, changing the LLM provider, or enabling auto-upload.

## Code conventions
Python 3.10+, type hints on public functions, `logging` not `print` (except `__main__` demos), small functions, pure functions where possible so they are testable. Paths via `core.config_loader.resolve_project_path`.

## Token economy rules
1. Targeted reads only: grep/glob or line ranges first; open only files strictly needed.
2. No blind exploration (`find`, `ls -R`, bulk directory reads) unless the owner asks.
3. Concise, factual replies: no repetitive summaries, no restating instructions; show only useful snippets or changes made.
4. Surgical edits: short, targeted, complete changes; do not rewrite long files unnecessarily.
5. Session hygiene: briefly remind the owner to run `/clear` when a task ends or the topic changes, and `/compact` when context gets heavy.
