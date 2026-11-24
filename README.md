# AutoSec-Pipeline

An autonomous, local-first cybersecurity content pipeline that automates CVE discovery, technical script generation in English, and multi-scene video episode rendering.

---

## Overview

`AutoSec-Pipeline` orchestrates four core stages to transform live vulnerability advisories into ready-to-publish video episodes and structured execution manifests:

1. **Self-Evaluation & Harness (`AutoHarnessLoop`, `SandboxExecutor`, `JudgeEvaluator`)**: Validates code/security checks and evaluates outputs against objective criteria.
2. **CVE Discovery (`NewsFetcher`)**: Queries the NVD REST API (2.0) over a configurable lookback window with retry logic, SSL certificate verification (`certifi`), and safe fallback advisories.
3. **Prompt Optimization & Script Writing (`PromptOptimizer`, `ScriptWriter`)**: Builds structured system/user prompts, cleans narration text for TTS compatibility, and generates multi-scene English JSON scripts using a local Ollama model (e.g., `qwen2.5-coder:7b`).
4. **Media Rendering & Manifest Logging (`CyberMediaGenerator`, `main.py`)**: Normalizes scene payloads, generates voiceovers via `edge-tts`, renders dark-themed technical slides locally using `Pillow` (`render_smart_scene_slide`), compiles the final `MP4` video with `MoviePy`, and logs run artifacts in `output/last_episode_manifest.json`.

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