"""Cross-scan model persistence — save and load trained ML models between scans.

When you scan an AWS WAF target, the model learns that "Base64 in Header bypasses."
Next time you scan ANY AWS WAF target, it loads that knowledge and tests those
patterns FIRST — dramatically faster and more effective.

Storage: ~/.gotestwaf/models/<waf_type>/<model_name>.pkl
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

DEFAULT_MODEL_DIR = Path.home() / ".gotestwaf" / "models"


def _get_waf_key(waf_name: str) -> str:
    """Normalize WAF name to filesystem-safe key."""
    # "AWS WAF (Amazon Web Services)" -> "aws-waf"
    key = waf_name.lower()
    for remove in ["(", ")", "inc.", "inc", "networks", "technologies"]:
        key = key.replace(remove, "")
    key = "-".join(key.split())[:30]
    # Remove non-alphanumeric except dash
    key = "".join(c if c.isalnum() or c == "-" else "" for c in key)
    return key or "generic"


def save_scan_knowledge(
    waf_name: str,
    target_url: str,
    bypass_patterns: dict[str, Any],
    model_metrics: dict[str, Any],
    inference_result: Any = None,
    model_dir: Path = DEFAULT_MODEL_DIR,
) -> Path | None:
    """Save learned bypass patterns from a completed scan.

    Args:
        waf_name: Detected WAF name.
        target_url: Scanned URL.
        bypass_patterns: Dict of encoder+placeholder -> bypass rate.
        model_metrics: ML training metrics.
        inference_result: Ruleset inference result.
        model_dir: Directory to save models.

    Returns:
        Path to saved knowledge file, or None if save failed.
    """
    try:
        waf_key = _get_waf_key(waf_name)
        waf_dir = model_dir / waf_key
        waf_dir.mkdir(parents=True, exist_ok=True)

        knowledge = {
            "waf_name": waf_name,
            "waf_key": waf_key,
            "target_url": target_url,
            "scan_time": time.time(),
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "bypass_patterns": bypass_patterns,
            "model_metrics": _sanitize_for_json(model_metrics),
        }

        # Add ruleset inference if available
        if inference_result is not None:
            from gotestwaf.scanner.ruleset_inference import InferenceResult
            if isinstance(inference_result, InferenceResult):
                knowledge["detected_rulesets"] = [
                    {"name": r.name, "vendor": r.vendor, "confidence": r.confidence}
                    for r in inference_result.detected if r.status == "detected"
                ]
                knowledge["missing_rulesets"] = [
                    {"name": r.name, "recommendation": r.recommendation, "confidence": r.confidence}
                    for r in inference_result.missing
                ]

        # Save as JSON (human-readable, portable)
        knowledge_path = waf_dir / "knowledge.json"
        knowledge_path.write_text(json.dumps(knowledge, indent=2, default=str), encoding="utf-8")

        # Also save scan history (append)
        history_path = waf_dir / "scan_history.jsonl"
        with history_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "url": target_url,
                "time": knowledge["scan_date"],
                # `get_metrics()` returns the field as `cv_f1_score`. Reading
                # `cv_f1` (the previous key name) silently returns 0, which
                # then causes `load_ml_model`'s gate at line ~280 to reject
                # every saved model because the cv_f1 < 0.5 check is always
                # true.
                "score": model_metrics.get("cv_f1_score", model_metrics.get("cv_f1", 0)),
                "bypasses": sum(v.get("bypass_count", 0) for v in bypass_patterns.values() if isinstance(v, dict)),
            }, default=str) + "\n")

        logger.info("Scan knowledge saved", path=str(knowledge_path), waf=waf_key)
        return knowledge_path

    except Exception as e:
        logger.warning("Failed to save scan knowledge", error=str(e))
        return None


def load_scan_knowledge(
    waf_name: str,
    model_dir: Path = DEFAULT_MODEL_DIR,
) -> dict[str, Any] | None:
    """Load previously learned bypass patterns for a WAF type.

    Args:
        waf_name: Detected WAF name.
        model_dir: Directory where models are stored.

    Returns:
        Knowledge dict with bypass patterns, or None if no prior knowledge.
    """
    try:
        waf_key = _get_waf_key(waf_name)
        knowledge_path = model_dir / waf_key / "knowledge.json"

        if not knowledge_path.exists():
            return None

        knowledge = json.loads(knowledge_path.read_text(encoding="utf-8"))

        # Check freshness — knowledge older than 30 days is stale
        scan_time = knowledge.get("scan_time", 0)
        age_days = (time.time() - scan_time) / 86400
        if age_days > 30:
            logger.info("Prior scan knowledge is stale", age_days=f"{age_days:.0f}", waf=waf_key)
            knowledge["is_stale"] = True
        else:
            knowledge["is_stale"] = False

        logger.info(
            "Loaded prior scan knowledge",
            waf=waf_key,
            from_url=knowledge.get("target_url", ""),
            age_days=f"{age_days:.1f}",
            patterns=len(knowledge.get("bypass_patterns", {})),
        )
        return knowledge

    except Exception as e:
        logger.warning("Failed to load scan knowledge", error=str(e))
        return None


def get_priority_payloads(knowledge: dict[str, Any]) -> list[dict[str, str]]:
    """Extract high-priority encoder+placeholder combos from prior knowledge.

    These are combos that bypassed in the previous scan — test them FIRST.
    """
    priorities: list[dict[str, str]] = []

    bypass_patterns = knowledge.get("bypass_patterns", {})
    for combo_key, stats in bypass_patterns.items():
        if not isinstance(stats, dict):
            continue
        bypass_rate = stats.get("bypass_rate", 0)
        if bypass_rate > 0.1:
            parts = combo_key.split("|", 1)
            if len(parts) == 2:
                priorities.append({
                    "encoder": parts[0],
                    "placeholder": parts[1],
                    "bypass_rate": bypass_rate,
                    "source": "prior_scan",
                })

    # Sort by bypass rate — most successful combos first
    priorities.sort(key=lambda x: -x.get("bypass_rate", 0))
    return priorities


def save_ml_model(
    waf_name: str,
    engine: Any,
    model_dir: Path = DEFAULT_MODEL_DIR,
) -> Path | None:
    """Persist a trained HybridMLEngine to disk for reuse in future scans.

    The model is keyed by WAF name, so the next scan against the same WAF type
    can load it and score payloads without having to learn from scratch.
    """
    if engine is None or not getattr(engine, "_is_trained", False):
        return None
    try:
        import sklearn  # noqa: F401 — ensure sklearn is importable
        import os, tempfile
        waf_key = _get_waf_key(waf_name)
        waf_dir = model_dir / waf_key
        waf_dir.mkdir(parents=True, exist_ok=True)
        model_path = waf_dir / "engine.joblib"
        meta_path = waf_dir / "engine.meta.json"

        # Atomic write — concurrent saves (e.g. scheduled scans) would
        # otherwise leave engine.joblib half-written on disk and the next
        # `joblib.load` would either crash or silently return garbage.
        # Write to a temp file in the same directory (so os.replace is atomic
        # on both POSIX and Windows), then rename.
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(waf_dir), suffix=".joblib.tmp")
        os.close(tmp_fd)
        try:
            engine.save(tmp_path)
            os.replace(tmp_path, str(model_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        meta = {
            "waf_name": waf_name,
            "waf_key": waf_key,
            "saved_at": time.time(),
            "saved_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sklearn_version": __import__("sklearn").__version__,
            "metrics": _sanitize_for_json(engine.get_metrics()) if hasattr(engine, "get_metrics") else {},
        }
        meta_tmp_fd, meta_tmp_path = tempfile.mkstemp(dir=str(waf_dir), suffix=".meta.json.tmp")
        os.close(meta_tmp_fd)
        try:
            with open(meta_tmp_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(meta, indent=2, default=str))
            os.replace(meta_tmp_path, str(meta_path))
        except Exception:
            try:
                os.unlink(meta_tmp_path)
            except OSError:
                pass
            raise

        logger.info("ML model saved", path=str(model_path), waf=waf_key)
        return model_path
    except Exception as e:
        logger.warning("Failed to save ML model", error=str(e))
        return None


def load_ml_model(
    waf_name: str,
    engine: Any,
    model_dir: Path = DEFAULT_MODEL_DIR,
    max_age_days: int = 30,
) -> bool:
    """Load a previously saved HybridMLEngine for this WAF type, if fresh.

    Returns True on success (engine is now trained and ready to score),
    False if no prior model exists, it is stale, or it fails to load.
    Never raises — silent no-op on any error.
    """
    if engine is None:
        return False
    try:
        waf_key = _get_waf_key(waf_name)
        model_path = model_dir / waf_key / "engine.joblib"
        meta_path = model_dir / waf_key / "engine.meta.json"
        if not model_path.exists():
            return False

        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                age_days = (time.time() - meta.get("saved_at", 0)) / 86400
                if age_days > max_age_days:
                    logger.info(
                        "Prior ML model is stale — ignoring",
                        waf=waf_key, age_days=f"{age_days:.0f}",
                    )
                    return False
                # Defense-in-depth: ignore models saved with very low cv_f1.
                # The save path already gates on cv_f1 >= 0.6, but older
                # on-disk models from previous versions may have slipped past.
                # Read the canonical `cv_f1_score` key (engine.get_metrics()
                # writes it under that name); fall back to the old `cv_f1`
                # key for backward-compat with pre-round-13 saved models.
                _saved_metrics = meta.get("metrics", {}) or {}
                saved_cv_f1 = float(
                    _saved_metrics.get("cv_f1_score", _saved_metrics.get("cv_f1", 0.0))
                )
                if saved_cv_f1 < 0.5:
                    logger.info(
                        "Prior ML model has low cv_f1 — ignoring",
                        waf=waf_key, cv_f1=round(saved_cv_f1, 4),
                    )
                    return False
                saved_sklearn = meta.get("sklearn_version", "")
                import sklearn
                if saved_sklearn and saved_sklearn != sklearn.__version__:
                    logger.info(
                        "Prior ML model built with different sklearn version",
                        saved=saved_sklearn, current=sklearn.__version__,
                    )
            except Exception:
                pass  # meta is advisory; proceed with load anyway

        engine.load(str(model_path))
        logger.info(
            "Prior ML model loaded — fast mode available",
            waf=waf_key, path=str(model_path),
        )
        return True
    except Exception as e:
        logger.warning("Failed to load prior ML model", error=str(e))
        return False


def get_scan_history(waf_name: str, model_dir: Path = DEFAULT_MODEL_DIR) -> list[dict[str, Any]]:
    """Get scan history for a WAF type."""
    try:
        waf_key = _get_waf_key(waf_name)
        history_path = model_dir / waf_key / "scan_history.jsonl"
        if not history_path.exists():
            return []
        history = []
        for line in history_path.read_text(encoding="utf-8").strip().split("\n"):
            if line:
                history.append(json.loads(line))
        return history
    except Exception:
        return []


def _sanitize_for_json(obj: Any) -> Any:
    """Convert non-JSON-serializable types."""
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(v) for v in obj]
    if isinstance(obj, float):
        if obj != obj:  # NaN
            return 0.0
        return round(obj, 6)
    if isinstance(obj, (int, str, bool, type(None))):
        return obj
    return str(obj)
