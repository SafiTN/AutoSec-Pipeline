# AutoSec-Pipeline

An autonomous, local-first cybersecurity content pipeline that automates CVE discovery, technical script generation in English, and multi-scene video episode rendering.

---

## Overview

`AutoSec-Pipeline` orchestrates four core stages to transform live vulnerability advisories into ready-to-publish video episodes and structured execution manifests:

1. **Self-Evaluation & Harness (`AutoHarnessLoop`, `SandboxExecutor`, `JudgeEvaluator`)**: Validates code/security checks and evaluates outputs against objective criteria. The sandbox limits (timeout, memory, output size, process count) are best-effort and are **not a security boundary** (see `docs/adr/0003-sandbox-limits.md`).
2. **CVE Discovery (`NewsFetcher`)**: Queries the NVD REST API (2.0) over a configurable lookback window with retry logic and SSL certificate verification (`certifi`). If NVD is unreachable the run stops with an error unless `nvd.allow_fallback: true` is set explicitly; fallback runs are marked `is_sample`. CVEs that already produced a video are recorded in `covered_cves.json` and are not selected again (see `docs/adr/0001-covered-cves-state-file.md`).
3. **Prompt Optimization & Script Writing (`PromptOptimizer`, `ScriptWriter`)**: Builds structured system/user prompts, cleans narration text for TTS compatibility, and generates multi-scene English JSON scripts using a local Ollama model (e.g., `qwen2.5-coder:7b`). Each script is fact-checked against the advisory data and for forbidden (offensive) terms, with bounded retries (`script_validation:`; see `docs/adr/0002-script-fact-check.md`).
4. **Media Rendering & Manifest Logging (`CyberMediaGenerator`, `main.py`)**: Normalizes scene payloads, generates voiceovers via `edge-tts`, renders dark-themed technical slides locally using `Pillow` (`render_smart_scene_slide`), compiles the final `MP4` video with `MoviePy`, and logs run artifacts in `output/last_episode_manifest.json` (keys include `harness_summary`, `selected_cve`, `is_sample`, `episode_script`, `prompt_version`, `output_video` and `render_error`). Sample runs are watermarked "SAMPLE" and use a `sample_` video filename; `python main.py` exits non-zero if no video was produced or the run aborts (e.g. NVD unreachable).

**Content policy:** scripts and slides are defensive only (no exploit code, payloads or step-by-step attack instructions), and every fact (CVE id, severity, CVSS, versions) must come from the advisory data. Disclose AI-generated content when publishing and respect YouTube policies; the pipeline never uploads anything.

---

## Project Structure

```text
AutoSec-Pipeline/
├── .github/
│   ├── dependabot.yml                 # Dependency update automation
│   └── workflows/
│       ├── auto_pipeline.yml          # CI: ruff, ruff format check, pytest + coverage gate
│       └── scheduled_dry_run.yml      # Weekly offline dry run (no NVD/Ollama)
├── assets/
│   └── fonts/                         # Bundled Inter fonts (SIL OFL 1.1) + OFL.txt
├── config/
│   └── settings.yaml                  # Central pipeline, LLM, and media configuration
├── core/
│   ├── agent_runner.py                # Local LLM execution wrapper (Ollama)
│   ├── config_loader.py               # Settings loader with deep-merge & path resolution
│   ├── harness_loop.py                # Self-evaluation optimization loop
│   └── prompt_optimizer.py            # Structured prompt builder for CVE scripts
├── modules/
│   ├── content_pipeline/
│   │   ├── media_generator.py         # Edge-TTS voiceover, Pillow slides & MoviePy video builder
│   │   ├── news_fetcher.py            # NVD CVE advisory fetcher & CVSS selector
│   │   ├── script_validator.py        # Script fact-check and forbidden-term validator
│   │   └── script_writer.py           # Multi-scene script generator
│   ├── cyber_agent/
│   │   ├── base_harness.py            # Agent harness base abstractions
│   │   └── sandbox_exec.py            # Isolated execution utilities
│   └── evaluation/
│       ├── __init__.py
│       ├── judge_evaluator.py         # Automated quality scoring logic
│       └── scoring_sets.json          # Evaluation benchmarks and criteria
├── docs/
│   ├── BACKLOG.md                     # Task backlog and acceptance criteria
│   └── adr/                           # Architecture decision records (0001-0003)
├── tests/                             # pytest suite (16 files, network and Ollama mocked)
├── .gitignore                         # Excludes virtual environments, caches, and generated media
├── main.py                            # End-to-end pipeline orchestrator
├── requirements.txt                   # Runtime dependencies
├── requirements-dev.txt               # Test and lint dependencies (pytest, pytest-cov, ruff)
└── ruff.toml                          # Ruff lint/format configuration
```
*(Note: `output/` (manifest and `covered_cves.json`), `output_media/` and `.sandbox_runs/` are generated at runtime and excluded from version control via `.gitignore`.)*

---

## Prerequisites

* **Python**: 3.10 or higher
* **Ollama**: Installed and running locally with your configured model pulled:
  ```bash
  ollama pull qwen2.5-coder:7b
  ```
* **FFmpeg**: Available in your system `PATH` (or bundled via `imageio-ffmpeg` through `MoviePy`) for `libx264` / `aac` video encoding.
* **Internet Access**: Required for querying NVD CVE advisories and synthesizing speech via `edge-tts`.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SafiTN/AutoSec-Pipeline.git
   cd AutoSec-Pipeline
   ```

2. **Create and activate a virtual environment**:
   * **Windows (CMD)**:
     ```cmd
     python -m venv venv
     venv\Scripts\activate
     ```
   * **Linux / macOS**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration

Pipeline behavior is controlled via `config/settings.yaml` (comments in that file are authoritative; defaults live in `core/config_loader.py`):

* **`project`**: `name`, `version`, `log_level`.
* **`paths`**: `output_dir`, `media_dir`, `default_video_filename`, `manifest_filename`, `covered_cves_filename`, `pending_review_filename` (default `pending_review.json`, under `output_dir`).
* **`review`** (human review gate, `docs/adr/0004-human-review-gate.md`): `enabled` (default `true`; never applies to sample runs), `cvss_threshold` (`9.0`; CVSS at or above it requires approval), `review_required` (`false`; `true` gates every non-sample run), `fail_closed_on_unknown_cvss` (`true`; unknown or non-numeric CVSS also requires review).
* **`ollama`**: `base_url`, `model` (`qwen2.5-coder:7b`), `timeout_sec`, `temperature`.
* **`ai`**: legacy provider block (`provider`, `base_url`, `model`, `timeout_sec`, `temperature`). `AgentRunner` uses it in preference to `ollama` when present, and the harness reads its `temperature`. Keep it in sync with `ollama`.
* **`nvd`**: `api_url`, `lookback_days`, `max_results`, `default_limit`, `timeout_sec`, `max_retries`, `allow_fallback` (default `false`; when `true`, an unreachable NVD yields a sample advisory marked `is_sample`).
* **`prompt_optimizer`** (prompt `PROMPT_VERSION = "v2"`): `language`, `style`, `default_max_scenes`, `hook_rotation`, `hook_styles` (`question`/`number`/`scenario`, picked deterministically from the CVE id), `max_bullets`, `max_bullet_chars`, `max_takeaway_chars`, `max_hook_words`. Each scene carries `key_takeaway` (one sentence) and `on_screen_bullets` (up to 3 short strings), both fact-checked like narration and rendered on the slides. Old 3-key scenes are still accepted.
* **`script_validation`**: `enabled`, `max_retries` (extra LLM attempts after the first), `forbidden_terms`.
* **`media`**:
  * `output_directory` / `slides_directory`: folders for audio and final `.mp4` videos / rendered `.png` slides.
  * `visual_mode`: `"slide"` (`render_smart_scene_slide`: dark styling, text wrapping, CVE/severity header).
  * `voice`: Edge-TTS voice (e.g. `en-US-GuyNeural`); canonical. `tts_voice` is a duplicate key that the media generator does not read.
  * `video_fps` and `resolution` (`width`/`height`, default `1280x720`, `24` fps); `video_fps` is canonical and `fps` is only a fallback.
  * `slide`: `fonts` (`regular`, `bold`, optional `mono`; bundled Inter fonts in `assets/fonts/`, SIL OFL 1.1, license in `assets/fonts/OFL.txt`), `sizes` (`title`, `body`, `header`, `badge`, `takeaway`), `min_font_size`, `margin`, `max_bullets`, and `sample_label` (watermark drawn on every slide of sample runs, default `SAMPLE`).
* **`sandbox`**: `timeout_sec`, `max_memory_mb`, `max_output_bytes`, `max_processes`, `work_root`, `allow_unlimited` (best-effort limits, not a security boundary).
* **`harness`**: `enabled_by_default`, `max_iterations`, `target_score`, `pass_threshold`.

---

## Usage

### Run the Full Pipeline
Ensure Ollama is running locally, then execute:

```bash
python main.py
```

**What happens during a run:**
1. Fetches the latest CVE advisories and selects the highest-severity candidate (`CVSS`).
2. Generates a structured multi-scene script via Ollama.
3. Synthesizes scene voiceovers (`MP3`) and renders dark-themed scene slides (`PNG`).
4. Compiles the synchronized video (`MP4`) and writes a detailed run summary to `output/last_episode_manifest.json`.

### Human Review Gate
When the gate applies (see `review:` above), `python main.py` validates the script, writes `output/pending_review.json` and stops before rendering, with manifest `review_status: "pending"`. Inspect the file, then run:

```bash
python main.py --approve   # render the video for the pending review
python main.py --reject    # discard it and mark the CVE covered
```

`review_status` in the manifest is `not_required`, `pending`, `approved` or `rejected`. Exit codes: `0` success, `1` error, `2` pending human review (not a failure). CI never passes `--approve`/`--reject`; it treats exit 2 as success and emits a notice.

### Test Media Generation Standalone
You can test slide rendering and video assembly independently without calling NVD or Ollama:

```bash
python modules/content_pipeline/media_generator.py
```

---

## Running Tests

Execute the unit test suite using `pytest`:

```bash
python -m pytest -v
```

Run with coverage (same gate as CI, fails below 86%):

```bash
pip install -r requirements-dev.txt
python -m pytest -v --cov=core --cov=modules --cov-report=term --cov-fail-under=86
```

Lint and format check (same as CI): `ruff check .` and `ruff format --check .` (config in `ruff.toml`).

---

## Scheduling

* **CI (GitHub Actions):** `.github/workflows/scheduled_dry_run.yml` runs weekly (Mondays 05:17 UTC) as an offline dry run: ruff, config validation and pytest. It never calls NVD or Ollama and uploads nothing. GitHub pauses scheduled workflows after 60 days without repository activity; re-enable the workflow in the Actions tab or push a commit.
* **Full local runs** (need Ollama and internet):
  * Linux/macOS cron, daily at 09:00: `0 9 * * * cd /path/to/AutoSec-Pipeline && ./venv/bin/python main.py >> output/cron.log 2>&1`
  * Windows Task Scheduler (adjust the project path):

    ```cmd
    schtasks /Create /SC DAILY /ST 09:00 /TN "AutoSecPipeline" /TR "cmd /c cd /d D:\path\to\AutoSec-Pipeline && venv\Scripts\python.exe main.py >> output\task.log 2>&1"
    ```

Scheduled runs never upload anything; auto-upload requires explicit owner approval.

---

## Roadmap

* [x] Pass `cve_id` and `severity` metadata from `main.py` into `CyberMediaGenerator.build_video` for header badges on every slide.
* [x] Add automated unit tests covering `CyberMediaGenerator.render_smart_scene_slide` (`tests/test_media_generator_slides.py`).
* [ ] Human review gate for high-severity CVEs before rendering (backlog T15).
* [ ] Hardening: hook word-limit warning and NVD summary prompt-injection sanitizing (backlog T21).
* [ ] Optional YouTube Data API v3 upload and metadata scheduling module (needs explicit owner approval).
