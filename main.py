import inspect
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.config_loader import load_settings, resolve_project_path
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


def _covered_cves_path(settings: Dict[str, Any]) -> str:
    """تحديد المسار المطلق لملف حالة الثغرات المُنشورة سابقاً (covered_cves.json)."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    output_dir = paths_cfg.get("output_dir", "output")
    covered_filename = paths_cfg.get("covered_cves_filename", "covered_cves.json")
    return str(resolve_project_path(os.path.join(output_dir, covered_filename)))


def _read_covered_cves_raw(settings: Dict[str, Any]) -> Dict[str, Any]:
    """قراءة ملف الثغرات المُغطاة بأمان: ملف مفقود أو تالف يُرجع قاموساً فارغاً دون توقف."""
    path = _covered_cves_path(settings)
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except json.JSONDecodeError as exc:
        logger.warning("[Main] covered_cves.json at %s is not valid JSON (%s); treating as empty.", path, exc)
        return {}

    if not isinstance(loaded, dict):
        logger.warning(
            "[Main] covered_cves.json at %s did not contain a JSON object; treating as empty.", path
        )
        return {}

    return loaded


def _load_covered_cve_ids(settings: Dict[str, Any]) -> Set[str]:
    """تحميل مجموعة معرّفات الثغرات التي سبق نشرها لتفادي التكرار بين التشغيلات."""
    return set(_read_covered_cves_raw(settings).keys())


def _record_covered_cve(settings: Dict[str, Any], cve_id: str) -> None:
    """تسجيل ثغرة حقيقية تم نشرها بنجاح في ملف الحالة الدائم عبر التشغيلات."""
    path = _covered_cves_path(settings)
    covered = _read_covered_cves_raw(settings)
    covered[cve_id] = datetime.now(timezone.utc).isoformat()

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(covered, f, indent=2, ensure_ascii=False)


def _select_primary_advisory(
    advisories: List[Dict[str, Any]],
    covered_cve_ids: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """اختيار الثغرة الأعلى خطورة (CVSS) من بين المرشحات غير المُغطاة سابقاً وذات درجة CVSS معروفة."""
    if not advisories:
        raise ValueError("No CVE advisories available to select from")

    covered_ids = covered_cve_ids or set()

    with_cvss = [item for item in advisories if item.get("cvss_score") is not None]
    if not with_cvss:
        raise ValueError(
            "No CVE advisories with a known CVSS score available to select from "
            f"(all {len(advisories)} candidate(s) had cvss_score=None)"
        )

    uncovered = [item for item in with_cvss if item.get("cve_id") not in covered_ids]
    if not uncovered:
        raise ValueError(
            "All CVE advisories with a known CVSS score have already been covered in a prior run "
            f"({len(with_cvss)} candidate(s) filtered out by covered_cves.json); "
            "wait for new CVEs, widen nvd.lookback_days/max_results, or prune covered_cves.json"
        )

    return max(uncovered, key=lambda item: float(item.get("cvss_score") or 0.0))

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
    cve_limit: Optional[int] = None,
    max_scenes: int = 3,
) -> Dict[str, Any]:
    """تشغيل الخط الكامل: التحقق الذاتي -> جلب الثغرات -> كتابة السيناريو -> إنتاج الفيديو."""
    settings = load_settings()
    effective_cve_limit = (
        cve_limit if cve_limit is not None else settings.get("nvd", {}).get("max_results", 10)
    )

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
    advisories = fetcher.fetch_latest_cves(limit=effective_cve_limit)
    covered_cve_ids = _load_covered_cve_ids(settings)
    selected_cve = _select_primary_advisory(advisories, covered_cve_ids)
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

    if generated_video is not None and not selected_cve.get("is_sample"):
        _record_covered_cve(settings, selected_cve["cve_id"])

    logger.info("[Main] Pipeline completed. Manifest saved to %s", manifest_path)
    return manifest


if __name__ == "__main__":
    try:
        result = run_pipeline(run_harness=False, cve_limit=3, max_scenes=3)
    except (NvdFetchError, ValueError) as exc:
        logger.error("[Main] Aborting: %s", exc)
        print(f"\n[ERROR] Pipeline aborted: {exc}")
        sys.exit(1)

    print("\n=== AutoSec-Pipeline Run Summary ===")
    print("CVE:", result["selected_cve"].get("cve_id"))
    print("Title:", result["episode_script"].get("episode_title"))
    print("Scenes count:", len(result["episode_script"].get("scenes", [])))
    print("Video output:", result.get("output_video"))