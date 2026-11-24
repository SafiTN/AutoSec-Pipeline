# AutoSec-Pipeline

An autonomous, local-first cybersecurity content pipeline that automates CVE discovery, technical script generation in English, and video episode rendering.

## Overview

`AutoSec-Pipeline` orchestrates four main stages:
1. **Self-Evaluation & Harness (`AutoHarnessLoop`, `SandboxExecutor`, `JudgeEvaluator`)**: Validates code/security checks and evaluates outputs against objective criteria.
2. **CVE Discovery (`NewsFetcher`)**: Queries the NVD REST API (`2.0`) over a configurable lookback window with retry logic, SSL certificate verification (`certifi`), and safe fallback advisories.
3. **Prompt Optimization & Script Writing (`PromptOptimizer`, `ScriptWriter`)**: Builds structured system/user prompts, cleans narration text for TTS compatibility, and generates multi-scene English JSON scripts using a local **Ollama** model (`qwen2.5-coder:7b`).
4. **Media Rendering & Manifest Logging (`CyberMediaGenerator`, `main.py`)**: Normalizes scene payloads, generates voiceover and video media (`edge-tts` + `moviepy`), and records run artifacts in `output/last_episode_manifest.json`.

## Project Structure

```text
AutoSec-Pipeline/
├── config/
│   └── settings.yaml
├── core/
│   ├── agent_runner.py
│   ├── config_loader.py
│   ├── harness_loop.py
│   └── prompt_optimizer.py
├── modules/
│   └── content_pipeline/
│       ├── media_generator.py
│       ├── news_fetcher.py
│       └── script_writer.py
├── output/
├── output_media/
├── main.py
├── requirements.txt
└── README.md