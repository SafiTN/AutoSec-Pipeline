# AutoSec-Pipeline

An autonomous, local-first cybersecurity content pipeline that automates CVE discovery, technical script generation in English, and multi-scene video episode rendering.

---

## Overview

`AutoSec-Pipeline` orchestrates four core stages to transform live vulnerability advisories into ready-to-publish video episodes and structured execution manifests:

1. **Self-Evaluation & Harness (`AutoHarnessLoop`, `SandboxExecutor`, `JudgeEvaluator`)**: Validates code/security checks and evaluates outputs against objective criteria.
2. **CVE Discovery (`NewsFetcher`)**: Queries the NVD REST API (2.0) over a configurable lookback window with retry logic, SSL certificate verification (`certifi`), and safe fallback advisories.
3. **Prompt Optimization & Script Writing (`PromptOptimizer`, `ScriptWriter`)**: Builds structured system/user prompts, cleans narration text for TTS compatibility, and generates multi-scene English JSON scripts using a local Ollama model (e.g., `qwen2.5-coder:7b`).
4. **Media Rendering & Manifest Logging (`CyberMediaGenerator`, `main.py`)**: Normalizes scene payloads, generates voiceovers via `edge-tts`, renders dark-themed technical slides locally using `Pillow` (`render_smart_scene_slide`), compiles the final `MP4` video with `MoviePy`, and logs run artifacts in `output/last_episode_manifest.json` (including `prompt_version`, `is_sample` and `render_error`; sample runs are watermarked "SAMPLE" and the run exits non-zero if no video was produced).

---

## Project Structure

```text
AutoSec-Pipeline/
├── .github/
│   └── workflows/
│       └── auto_pipeline.yml          # CI/CD workflow for automated checks
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
│   │   └── script_writer.py           # Multi-scene script generator
│   ├── cyber_agent/
│   │   ├── base_harness.py            # Agent harness base abstractions
│   │   └── sandbox_exec.py            # Isolated execution utilities
│   └── evaluation/
│       ├── __init__.py
│       ├── judge_evaluator.py         # Automated quality scoring logic
│       └── scoring_sets.json          # Evaluation benchmarks and criteria
├── tests/
│   └── test_pipeline_core.py          # Unit tests for core pipeline modules
├── .gitignore                         # Excludes virtual environments, caches, and generated media
├── main.py                            # End-to-end pipeline orchestrator
└── requirements.txt                   # Python dependencies
```
*(Note: `output/` and `output_media/` directories are generated automatically at runtime and excluded from version control via `.gitignore`.)*

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
   git clone https://github.com/<YOUR_USERNAME>/AutoSec-Pipeline.git
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

Pipeline behavior is controlled via `config/settings.yaml`:

* **LLM Settings**: Ollama endpoint URL, model name (`qwen2.5-coder:7b`), temperature, and timeout parameters.
* **NVD / Advisory Settings**: Lookback window, maximum advisories fetched, and fallback behavior.
* **Prompt Settings** (`prompt_optimizer:`, prompt `PROMPT_VERSION = "v2"`): `hook_rotation` and `hook_styles` (`question`/`number`/`scenario`, picked deterministically from the CVE id), `max_bullets`, `max_bullet_chars`, `max_takeaway_chars`, `max_hook_words`. Each scene now also carries `key_takeaway` (one sentence) and `on_screen_bullets` (up to 3 short strings). Both are fact-checked like narration; slide rendering of them is not implemented yet. Old 3-key scenes are still accepted.
* **Media Settings**:
  * `output_directory`: Target folder for generated audio and final `.mp4` videos.
  * `slides_directory`: Target folder for rendered `.png` scene slides.
  * `visual_mode`: `"slide"` (uses `render_smart_scene_slide` with dark cybersecurity styling, automatic text wrapping, and CVE/Severity headers).
  * `voice`: Edge-TTS voice identifier (e.g., `en-US-GuyNeural`).
  * `resolution` & `video_fps`: Video dimensions (default `1280x720`) and frame rate (default `24`).

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

---

## Roadmap

* [ ] Pass `cve_id` and `severity` metadata directly from `main.py` into `CyberMediaGenerator.build_video` for full header badges on every slide.
* [ ] Add automated unit tests covering `CyberMediaGenerator.render_smart_scene_slide`.
* [ ] Optional YouTube Data API v3 upload and metadata scheduling module.