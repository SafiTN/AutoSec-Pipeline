import argparse
import hashlib
import hmac
import json
import logging
import math
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, NoReturn, Optional, Set, TypedDict

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.config_loader import get_review_config, load_settings, resolve_project_path
from core.harness_loop import AutoHarnessLoop
from modules.content_pipeline.media_generator import CyberMediaGenerator
from modules.content_pipeline.news_fetcher import NewsFetcher, NvdFetchError
from modules.content_pipeline.script_validator import validate_script
from modules.content_pipeline.script_writer import ScriptWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AutoSec.Main")


def _output_dir(settings: Dict[str, Any]) -> str:
    """Return the absolute output directory from paths.output_dir."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    return str(resolve_project_path(paths_cfg.get("output_dir", "output")))


def _manifest_path(settings: Dict[str, Any]) -> str:
    """Return the absolute manifest path (paths.output_dir / paths.manifest_filename)."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    output_dir = paths_cfg.get("output_dir", "output")
    manifest_filename = paths_cfg.get("manifest_filename", "last_episode_manifest.json")
    return str(resolve_project_path(os.path.join(output_dir, manifest_filename)))


def _video_filename(settings: Dict[str, Any], is_sample: bool) -> str:
    """Return the video file name from paths.default_video_filename (sample_ prefix for samples)."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    name = paths_cfg.get("default_video_filename", "cyber_episode.mp4")
    name = Path(str(name)).name  # strip any directory parts so '..' cannot escape
    if name in ("", ".", ".."):
        name = "cyber_episode.mp4"
    return f"sample_{name}" if is_sample else name


def _covered_cves_path(settings: Dict[str, Any]) -> str:
    """Return the absolute path of the covered-CVE state file (covered_cves.json)."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    output_dir = paths_cfg.get("output_dir", "output")
    covered_filename = paths_cfg.get("covered_cves_filename", "covered_cves.json")
    return str(resolve_project_path(os.path.join(output_dir, covered_filename)))


def _read_covered_cves_raw(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Read the covered-CVE file safely: a missing or corrupt file yields an empty dict."""
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
        logger.warning("[Main] covered_cves.json at %s did not contain a JSON object; treating as empty.", path)
        return {}

    return loaded


def _load_covered_cve_ids(settings: Dict[str, Any]) -> Set[str]:
    """Load the set of CVE ids already published, to avoid repeats across runs."""
    return set(_read_covered_cves_raw(settings).keys())


def _record_covered_cve(settings: Dict[str, Any], cve_id: str) -> None:
    """Record a real, successfully rendered CVE in the persistent state file."""
    path = _covered_cves_path(settings)
    covered = _read_covered_cves_raw(settings)
    covered[cve_id] = datetime.now(timezone.utc).isoformat()

    _atomic_write_json(path, covered)


def _select_primary_advisory(
    advisories: List[Dict[str, Any]],
    covered_cve_ids: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Pick the highest-CVSS advisory among uncovered candidates with a known CVSS score."""
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
    """Ensure the keys build_video expects (e.g. visual_text) are present."""
    normalized: List[Dict[str, Any]] = []
    for idx, sc in enumerate(scenes, start=1):
        item = dict(sc)
        fallback_visual = item.get("visual_text") or item.get("visual_cue") or item.get("title") or f"Scene {idx}"
        item["visual_text"] = str(fallback_visual).strip()
        if "narration" not in item:
            item["narration"] = ""
        if "title" not in item:
            item["title"] = f"Scene {idx}"
        normalized.append(item)
    return normalized


_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
PENDING_SCHEMA_VERSION = 1
_PENDING_REQUIRED_KEYS = (
    "schema_version",
    "status",
    "reason",
    "created_at",
    "decided_at",
    "prompt_version",
    "selected_cve",
    "episode_script",
    "script_sha256",
)


class PendingReview(TypedDict):
    """Schema of output/pending_review.json (ADR 0004)."""

    schema_version: int
    status: str  # pending | approved | rejected
    reason: str  # cvss>=threshold | review_required | unknown_cvss
    created_at: str
    decided_at: Optional[str]
    prompt_version: Optional[str]
    selected_cve: Dict[str, Any]
    episode_script: Dict[str, Any]
    script_sha256: str


def _pending_review_path(settings: Dict[str, Any]) -> str:
    """Return the absolute path of the pending-review file (under paths.output_dir)."""
    paths_cfg = settings.get("paths", {}) if settings else {}
    output_dir = paths_cfg.get("output_dir", "output")
    name = Path(str(paths_cfg.get("pending_review_filename", "pending_review.json"))).name
    if name in ("", ".", ".."):
        name = "pending_review.json"
    return str(resolve_project_path(os.path.join(output_dir, name)))


def _review_sha256(selected_cve: Dict[str, Any], episode_script: Dict[str, Any]) -> str:
    """SHA-256 (hex) of canonical JSON of {selected_cve, episode_script} (ADR 0004, decision 1)."""
    payload = {"selected_cve": selected_cve, "episode_script": episode_script}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def should_require_review(advisory: Dict[str, Any], review_cfg: Dict[str, Any], is_sample: bool) -> Optional[str]:
    """Return the gate reason (cvss>=threshold | review_required | unknown_cvss) or None if no review is needed."""
    if is_sample:
        return None
    if not review_cfg.get("enabled", True):
        logger.warning("[Main] review.enabled is false: the human review gate is DISABLED for this run.")
        return None

    raw = advisory.get("cvss_score")
    cvss: Optional[float] = None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and not math.isnan(raw):
        cvss = float(raw)

    if cvss is not None and cvss >= float(review_cfg["cvss_threshold"]):
        return "cvss>=threshold"
    if str(advisory.get("severity") or "").strip().upper() in ("CRITICAL", "UNKNOWN"):
        return "severity"  # gated regardless of fail_closed_on_unknown_cvss
    if review_cfg.get("review_required", False):
        return "review_required"
    if cvss is None and review_cfg.get("fail_closed_on_unknown_cvss", True):
        return "unknown_cvss"
    return None


def _atomic_write_json(path: str, data: Any) -> None:
    """Write JSON via a temp file in the same directory plus os.replace (atomic)."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _write_pending_review(
    settings: Dict[str, Any], selected_cve: Dict[str, Any], episode_script: Dict[str, Any], reason: str
) -> str:
    """Write the pending-review file atomically and return its path."""
    pending: PendingReview = {
        "schema_version": PENDING_SCHEMA_VERSION,
        "status": "pending",
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "decided_at": None,
        "prompt_version": episode_script.get("prompt_version"),
        "selected_cve": selected_cve,
        "episode_script": episode_script,
        "script_sha256": _review_sha256(selected_cve, episode_script),
    }
    path = _pending_review_path(settings)
    _atomic_write_json(path, pending)
    return path


def _load_pending_review(settings: Dict[str, Any]) -> PendingReview:
    """Load and structurally validate the pending file. Raises ValueError when missing, corrupt or not pending."""
    path = _pending_review_path(settings)
    if not os.path.isfile(path):
        raise ValueError(f"No pending review found at {path}; nothing to approve or reject")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Pending review file {path} is corrupt: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Pending review file {path} is corrupt: not a JSON object")
    missing = [k for k in _PENDING_REQUIRED_KEYS if k not in data]
    if missing:
        raise ValueError(f"Pending review file {path} is corrupt: missing keys {missing}")
    if data["schema_version"] != PENDING_SCHEMA_VERSION:
        raise ValueError(f"Pending review file {path} has unsupported schema_version {data['schema_version']!r}")
    if not isinstance(data["selected_cve"], dict) or not isinstance(data["episode_script"], dict):
        raise ValueError(f"Pending review file {path} is corrupt: selected_cve/episode_script must be objects")
    if not isinstance(data["selected_cve"].get("cve_id"), str) or not data["selected_cve"]["cve_id"]:
        raise ValueError(f"Pending review file {path} is corrupt: selected_cve has no cve_id")
    if data["status"] != "pending":
        raise ValueError(f"Pending review file {path} has status {data['status']!r}, expected 'pending'")
    return data  # type: ignore[return-value]


def _archive_pending_review(settings: Dict[str, Any], pending: PendingReview, status: str) -> str:
    """Archive the pending file as pending_review.<status>.<UTC ts>.json with updated status; never delete."""
    path = _pending_review_path(settings)
    now = datetime.now(timezone.utc)
    updated = dict(pending)
    updated["status"] = status
    updated["decided_at"] = now.isoformat()

    base, ext = os.path.splitext(path)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    archive_path = f"{base}.{status}.{stamp}{ext}"
    counter = 1
    while os.path.exists(archive_path):  # never overwrite an earlier archive
        archive_path = f"{base}.{status}.{stamp}.{counter}{ext}"
        counter += 1
    os.replace(path, archive_path)  # single rename: no moment with two copies of the state
    _atomic_write_json(archive_path, updated)
    return archive_path


def _pending_result(pending: Mapping[str, Any], path: str, render_error: Optional[str] = None) -> Dict[str, Any]:
    """Result dict for a run that stopped at (or remains in) the pending-review state. No manifest is written."""
    return {
        "review_status": "pending",
        "review_reason": pending["reason"],
        "pending_review_path": path,
        "selected_cve": pending["selected_cve"],
        "episode_script": pending["episode_script"],
        "is_sample": False,
        "prompt_version": pending["prompt_version"],
        "output_video": None,
        "render_error": render_error,
    }


def _render_video(
    settings: Dict[str, Any], selected_cve: Dict[str, Any], episode_script: Dict[str, Any], is_sample: bool
) -> "tuple[Optional[str], Optional[str]]":
    """Render the episode. Returns (video_path, render_error); exactly one is None."""
    os.makedirs(_output_dir(settings), exist_ok=True)
    final_video_name = _video_filename(settings, is_sample)
    media_scenes = _normalize_scenes_for_media(episode_script.get("scenes", []))
    media_gen = CyberMediaGenerator(settings=settings)
    try:
        returned = media_gen.build_video(
            media_scenes,
            final_video_name,
            selected_cve.get("cve_id"),
            selected_cve.get("severity"),
            is_sample=is_sample,
        )
        if isinstance(returned, str) and os.path.isfile(returned):
            return returned, None
        logger.error("[Main] build_video did not produce a file (returned %r).", returned)
        return None, "video file was not produced"
    except Exception as exc:
        logger.error("[Main] Video generation failed; continuing without video.", exc_info=True)
        return None, f"video generation failed: {type(exc).__name__}"


def _write_manifest(settings: Dict[str, Any], manifest: Dict[str, Any]) -> str:
    manifest_path = _manifest_path(settings)
    _atomic_write_json(manifest_path, manifest)
    return manifest_path


def _approve_pending(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Approve the pending episode: verify hash, re-validate, render from the stored script, archive."""
    pending = _load_pending_review(settings)
    path = _pending_review_path(settings)
    episode_script = pending["episode_script"]
    selected_cve = pending["selected_cve"]

    if not _CVE_ID_RE.fullmatch(str(selected_cve.get("cve_id"))):
        raise ValueError(f"Pending review {path} has an invalid cve_id {selected_cve.get('cve_id')!r}")
    if selected_cve.get("is_sample"):
        raise ValueError(f"Pending review {path} refers to a sample advisory; refusing to approve")
    if not hmac.compare_digest(_review_sha256(selected_cve, episode_script), str(pending["script_sha256"])):
        raise ValueError(
            f"Pending review {path} was modified after creation (script_sha256 mismatch); "
            "refusing to approve. Use --reject and rerun to regenerate the script."
        )
    if episode_script.get("cve_id") != selected_cve.get("cve_id"):
        raise ValueError(
            f"Pending review {path} is inconsistent: episode_script cve_id "
            f"{episode_script.get('cve_id')!r} != selected_cve cve_id {selected_cve.get('cve_id')!r}"
        )

    rules = settings.get("script_validation", {}) or {}
    if rules.get("enabled", True):
        scenes = episode_script.get("scenes")
        if not isinstance(scenes, list):
            raise ValueError(f"Pending review {path} is corrupt: episode_script has no scenes list")
        violations = validate_script(ScriptWriter._validation_view(scenes), selected_cve, rules)
        if violations:
            raise ValueError(
                f"Stored script for {selected_cve['cve_id']} failed re-validation: " + "; ".join(violations)
            )

    logger.info("[Main] Approving pending review for %s; rendering stored script.", selected_cve["cve_id"])
    video, render_error = _render_video(settings, selected_cve, episode_script, False)
    if video is None:
        logger.error("[Main] Approve failed (%s); pending file left in place for retry.", render_error)
        return _pending_result(pending, path, render_error)

    approved_at = datetime.now(timezone.utc).isoformat()
    manifest = {
        "harness_summary": {"skipped": True},
        "selected_cve": selected_cve,
        "is_sample": False,
        "episode_script": episode_script,
        "prompt_version": episode_script.get("prompt_version"),
        "output_video": video,
        "render_error": None,
        "review_status": "approved",
        "approved_at": approved_at,
    }
    manifest_path = _write_manifest(settings, manifest)
    _record_covered_cve(settings, selected_cve["cve_id"])
    archived = _archive_pending_review(settings, pending, "approved")
    logger.info("[Main] Approved. Manifest saved to %s; pending file archived to %s", manifest_path, archived)
    return manifest


def _reject_pending(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Reject the pending episode: mark the CVE covered and archive the file (no render, no manifest)."""
    pending = _load_pending_review(settings)
    cve_id = pending["selected_cve"]["cve_id"]
    _record_covered_cve(settings, cve_id)
    archived = _archive_pending_review(settings, pending, "rejected")
    logger.info("[Main] Rejected %s; marked covered; pending file archived to %s", cve_id, archived)
    return {
        "review_status": "rejected",
        "selected_cve": pending["selected_cve"],
        "episode_script": pending["episode_script"],
        "is_sample": False,
        "output_video": None,
        "render_error": None,
        "archived_review_path": archived,
    }


def run_pipeline(
    run_harness: bool = False,
    cve_limit: Optional[int] = None,
    max_scenes: int = 3,
    *,
    approve: bool = False,
    reject: bool = False,
) -> Dict[str, Any]:
    """Run the full pipeline: self-check -> fetch CVEs -> write script -> (review gate) -> render video.

    approve/reject act on an existing pending review (ADR 0004) instead of running the pipeline.
    A result with review_status "pending" means no video was rendered and a human decision is needed.
    """
    if approve and reject:
        raise ValueError("approve and reject are mutually exclusive")
    settings = load_settings()
    if approve:
        return _approve_pending(settings)
    if reject:
        return _reject_pending(settings)

    review_cfg = get_review_config(settings)
    pending_path = _pending_review_path(settings)
    if os.path.isfile(pending_path):
        pending = _load_pending_review(settings)
        logger.warning(
            "[Main] A review is pending for %s at %s. Run `python main.py --approve` or `--reject` first.",
            pending["selected_cve"].get("cve_id"),
            pending_path,
        )
        return _pending_result(pending, pending_path)

    effective_cve_limit = cve_limit if cve_limit is not None else settings.get("nvd", {}).get("max_results", 10)

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

    is_sample = bool(selected_cve.get("is_sample", False))
    episode_title = episode_script.get("episode_title", "AutoSec Episode")
    if is_sample:
        episode_title = f"[SAMPLE] {episode_title}"
        episode_script["episode_title"] = episode_title

    review_reason = should_require_review(selected_cve, review_cfg, is_sample)
    if review_reason is not None:
        written_path = _write_pending_review(settings, selected_cve, episode_script, review_reason)
        logger.warning(
            "[Main] Human review required for %s (reason: %s). Script saved to %s; no video rendered. "
            "Run `python main.py --approve` to render or `python main.py --reject` to discard.",
            selected_cve.get("cve_id"),
            review_reason,
            written_path,
        )
        return _pending_result(
            {
                "reason": review_reason,
                "selected_cve": selected_cve,
                "episode_script": episode_script,
                "prompt_version": episode_script.get("prompt_version"),
            },
            written_path,
        )

    logger.info("[Main] Step 4/4: Generating video via CyberMediaGenerator...")
    generated_video, render_error = _render_video(settings, selected_cve, episode_script, is_sample)

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
        "prompt_version": episode_script.get("prompt_version"),
        "output_video": generated_video,
        "render_error": render_error,
        "review_status": "not_required",
    }

    manifest_path = _write_manifest(settings, manifest)

    if generated_video is not None and not selected_cve.get("is_sample"):
        _record_covered_cve(settings, selected_cve["cve_id"])

    logger.info("[Main] Pipeline completed. Manifest saved to %s", manifest_path)
    return manifest


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PENDING_REVIEW = 2


class _ExitOneArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors, which would collide with EXIT_PENDING_REVIEW; use 1 instead."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = _ExitOneArgumentParser(description="AutoSec-Pipeline: CVE advisory to video episode.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--approve", action="store_true", help="approve the pending review and render the video")
    group.add_argument("--reject", action="store_true", help="reject the pending review and mark the CVE covered")
    return parser


def _cli(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point. Returns 0 (done), 1 (error) or 2 (pending review)."""
    args = _build_arg_parser().parse_args(argv)
    try:
        result = run_pipeline(run_harness=False, cve_limit=3, max_scenes=3, approve=args.approve, reject=args.reject)
    except (NvdFetchError, ValueError) as exc:
        logger.error("[Main] Aborting: %s", exc)
        print(f"\n[ERROR] Pipeline aborted: {exc}")
        return EXIT_ERROR

    status = result.get("review_status")
    if status == "rejected":
        print("Rejected:", result["selected_cve"].get("cve_id"), "(marked covered; archived)")
        return EXIT_OK
    if status == "pending":
        if result.get("render_error"):
            logger.error("[Main] Approve failed: %s (pending review kept for retry)", result["render_error"])
            return EXIT_ERROR
        print("Review pending for", result["selected_cve"].get("cve_id"), "->", result.get("pending_review_path"))
        print("Run `python main.py --approve` or `python main.py --reject`.")
        return EXIT_PENDING_REVIEW

    print("\n=== AutoSec-Pipeline Run Summary ===")
    print("CVE:", result["selected_cve"].get("cve_id"))
    print("Title:", result["episode_script"].get("episode_title"))
    print("Scenes count:", len(result["episode_script"].get("scenes", [])))
    print("Video output:", result.get("output_video"))
    if not result.get("output_video"):
        logger.error("[Main] Video was not produced: %s", result.get("render_error"))
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    exit_code = _cli()
    if exit_code != EXIT_OK:
        sys.exit(exit_code)
