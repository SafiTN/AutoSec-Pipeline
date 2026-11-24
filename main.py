import inspect
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.config_loader import load_settings
from core.harness_loop import AutoHarnessLoop
from modules.content_pipeline.media_generator import CyberMediaGenerator
from modules.content_pipeline.news_fetcher import NewsFetcher, NvdFetchError
from modules.content_pipeline.script_writer import ScriptWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AutoSec.Main")


def _invoke_media_generator(
    media_gen: CyberMediaGenerator,
    scenes: List[Dict[str, str]],
    episode_title: str,
    output_path: str,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> Optional[str]:
    """استدعاء وحدة توليد الفيديو بمرونة عبر أسماء الدوال الشائعة في CyberMediaGenerator."""
    candidate_methods = [
        "generate_video",
        "create_video",
        "render_video",
        "build_video",
        "generate_episode",
        "create_episode",
    ]

    for method_name in candidate_methods:
        fn = getattr(media_gen, method_name, None)
        if not callable(fn):
            continue

        sig = inspect.signature(fn)
        params = sig.parameters
        kwargs: Dict[str, Any] = {}

        for name in params:
            if name == "self":
                continue
            if name in {"scenes", "script_scenes", "items"}:
                kwargs[name] = scenes
            elif name in {"title", "episode_title", "topic"}:
                kwargs[name] = episode_title
            elif name in {"output_path", "out_path", "filename", "output_file"}:
                kwargs[name] = output_path
            elif name in {"voice", "tts_voice"}:
                kwargs[name] = "en-US-GuyNeural"
            elif name == "cve_id" and cve_id:
                kwargs[name] = cve_id
            elif name == "severity" and severity:
                kwargs[name] = severity

        try:
            if kwargs:
                result = fn(**kwargs)
            else:
                req_count = sum(
                    1
                    for p in params.values()
                    if p.default is inspect.Parameter.empty
                    and p.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                )
                positional_args = [scenes, output_path] if req_count >= 2 else [scenes]
                result = fn(*positional_args)

            if isinstance(result, str) and result.strip():
                return result
            if os.path.exists(output_path):
                return output_path
            return output_path
        except TypeError as exc:
            logger.warning("[Main] Signature mismatch for MediaGenerator.%s: %s", method_name, exc)
            continue

    logger.error("[Main] No compatible video generation method found on MediaGenerator.")
    return None


def _select_primary_advisory(advisories: List[Dict[str, Any]]) -> Dict[str, Any]:
    """اختيار الثغرة الأعلى خطورة (CVSS) من القائمة المجلوبة."""
    if not advisories:
        raise ValueError("No CVE advisories available to select from")
    return max(advisories, key=lambda item: float(item.get("cvss_score") or 0.0))

def _normalize_scenes_for_media(scenes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """ضمان وجود المفاتيح التي تتوقعها build_video مثل visual_text."""
    normalized: List[Dict[str, Any]] = []
    for idx, sc in enumerate(scenes, start=1):
        item = dict(sc)
        fallback_visual = (
            item.get("visual_text")
            or item.get("visual_cue")
            or item.get("title")
            or f"Scene {idx}"
        )
        item["visual_text"] = str(fallback_visual).strip()
        if "narration" not in item:
            item["narration"] = ""
        if "title" not in item:
            item["title"] = f"Scene {idx}"
        normalized.append(item)
    return normalized

def run_pipeline(
    run_harness: bool = False,
    cve_limit: int = 3,
    max_scenes: int = 3,
) -> Dict[str, Any]:
    """تشغيل الخط الكامل: التحقق الذاتي -> جلب الثغرات -> كتابة السيناريو -> إنتاج الفيديو."""
    settings = load_settings()

    harness_summary: Dict[str, Any] = {}
    if run_harness:
        logger.info("[Main] Step 1/4: Running AutoHarnessLoop...")
        harness = AutoHarnessLoop(settings=settings)
        harness_summary = harness.run_optimization_loop()
        logger.info(
            "[Main] Harness finished -> Pass Rate: %.2f%% | Avg Score: %.2f/100",
            harness_summary.get("pass_rate", 0.0),
            harness_summary.get("average_score", 0.0),
        )
    else:
        logger.info("[Main] Step 1/4: Skipping AutoHarnessLoop (run_harness=False).")

    logger.info("[Main] Step 2/4: Fetching latest CVEs via NewsFetcher...")
    fetcher = NewsFetcher(settings=settings)
    advisories = fetcher.fetch_latest_cves(limit=cve_limit)
    selected_cve = _select_primary_advisory(advisories)
    logger.info(
        "[Main] Selected CVE: %s (Severity: %s, CVSS: %s)",
        selected_cve.get("cve_id"),
        selected_cve.get("severity"),
        selected_cve.get("cvss_score"),
    )

    logger.info("[Main] Step 3/4: Generating English video script via ScriptWriter...")
    writer = ScriptWriter(settings=settings)
    episode_script = writer.generate_episode_script(selected_cve, max_scenes=max_scenes)
    scenes = episode_script.get("scenes", [])

    is_sample = bool(selected_cve.get("is_sample", False))
    episode_title = episode_script.get("episode_title", "AutoSec Episode")
    if is_sample:
        episode_title = f"[SAMPLE] {episode_title}"
        episode_script["episode_title"] = episode_title

    logger.info("[Main] Step 4/4: Generating video via CyberMediaGenerator...")
    os.makedirs("output", exist_ok=True)
    output_video_path = os.path.abspath("autosec_master_episode.mp4")

    media_scenes = _normalize_scenes_for_media(scenes)
    media_gen = CyberMediaGenerator(settings=settings)
    generated_video = _invoke_media_generator(
        media_gen=media_gen,
        scenes=media_scenes,
        episode_title=episode_title,
        output_path=output_video_path,
        cve_id=selected_cve.get("cve_id"),
        severity=selected_cve.get("severity"),
    )

    manifest = {
        "harness_summary": {
            "pass_rate": harness_summary.get("pass_rate"),
            "average_score": harness_summary.get("average_score"),
            "passed_count": harness_summary.get("passed_count"),
            "total_tasks": harness_summary.get("total_tasks"),
        }
        if harness_summary
        else {"skipped": True},
        "selected_cve": selected_cve,
        "is_sample": is_sample,
        "episode_script": episode_script,
        "output_video": generated_video,
    }

    manifest_path = os.path.join("output", "last_episode_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    logger.info("[Main] Pipeline completed. Manifest saved to %s", manifest_path)
    return manifest


if __name__ == "__main__":
    try:
        result = run_pipeline(run_harness=False, cve_limit=3, max_scenes=3)
    except (NvdFetchError, ValueError) as exc:
        logger.error("[Main] Aborting: %s", exc)
        print(f"\n[ERROR] NVD fetch failed and nvd.allow_fallback is not enabled: {exc}")
        sys.exit(1)

    print("\n=== AutoSec-Pipeline Run Summary ===")
    print("CVE:", result["selected_cve"].get("cve_id"))
    print("Title:", result["episode_script"].get("episode_title"))
    print("Scenes count:", len(result["episode_script"].get("scenes", [])))
    print("Video output:", result.get("output_video"))