"""
/api/scan  –  Upload & analyse one or more files.

POST /api/scan/upload
    multipart/form-data  files[]=<file> …
    Returns { scan_id, results[] }

GET  /api/scan/<scan_id>
    Returns cached result for a previous scan
"""

import os
import uuid
import hashlib
import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from flask import Blueprint, request, jsonify, current_app

from utils.clamav_scanner   import scan_with_clamav
from utils.yara_scanner     import scan_with_yara
from utils.virustotal       import query_virustotal
from utils.file_analyzer    import analyze_file_metadata
from utils.network_analyzer import analyze_network_patterns
from utils.entropy          import calculate_entropy
from utils.threat_scorer    import compute_threat_score

logger    = logging.getLogger("neurovirus.scan")
scan_bp   = Blueprint("scan", __name__)

# Simple in-process cache  (use Redis in production)
_scan_cache: Dict[str, Any] = {}

ALLOWED_MAX_SIZE = 256 * 1024 * 1024   # 256 MB


# ── helpers ──────────────────────────────────────────────────────────────────

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_upload(file_storage) -> str:
    """Save an uploaded file to the upload dir and return its path."""
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    safe_name  = f"{uuid.uuid4().hex}_{Path(file_storage.filename).name}"
    dest       = os.path.join(upload_dir, safe_name)
    file_storage.save(dest)
    return dest


def _scan_single_file(path: str, original_name: str) -> Dict[str, Any]:
    """Run all analysis engines on one file and return a result dict."""
    start = time.time()
    logger.info("Scanning: %s (%s)", original_name, path)

    # ── 1. File metadata ─────────────────────────────────────────────────────
    meta = analyze_file_metadata(path, original_name)

    # ── 2. Hashes ────────────────────────────────────────────────────────────
    sha256 = _sha256(path)
    md5    = _md5(path)

    # ── 3. Entropy ───────────────────────────────────────────────────────────
    entropy_result = calculate_entropy(path)

    # ── 4. ClamAV ────────────────────────────────────────────────────────────
    clam_result = scan_with_clamav(
        path,
        host=current_app.config["CLAMAV_HOST"],
        port=current_app.config["CLAMAV_PORT"],
    )

    # ── 5. YARA ──────────────────────────────────────────────────────────────
    yara_result = scan_with_yara(path, current_app.config["YARA_RULES_DIR"])

    # ── 6. VirusTotal hash lookup ─────────────────────────────────────────────
    vt_result = query_virustotal(
        sha256,
        api_key=current_app.config["VIRUSTOTAL_API_KEY"],
    )

    # ── 7. Network-pattern analysis (static strings) ─────────────────────────
    network_result = analyze_network_patterns(path)

    # ── 8. Aggregate threat score ─────────────────────────────────────────────
    threat_score, threat_level = compute_threat_score(
        clam=clam_result,
        yara=yara_result,
        vt=vt_result,
        entropy=entropy_result,
        network=network_result,
        meta=meta,
    )

    elapsed = round(time.time() - start, 3)

    return {
        "file_name"    : original_name,
        "file_size"    : os.path.getsize(path),
        "sha256"       : sha256,
        "md5"          : md5,
        "scan_time_s"  : elapsed,
        "metadata"     : meta,
        "entropy"      : entropy_result,
        "clamav"       : clam_result,
        "yara"         : yara_result,
        "virustotal"   : vt_result,
        "network"      : network_result,
        "threat_score" : threat_score,
        "threat_level" : threat_level,
    }


# ── routes ───────────────────────────────────────────────────────────────────

@scan_bp.route("/upload", methods=["POST"])
def upload_and_scan():
    """Accept one or more files, scan them, return results."""
    uploaded_files = request.files.getlist("files[]")
    if not uploaded_files:
        return jsonify({"error": "No files provided"}), 400

    scan_id = uuid.uuid4().hex
    results: List[Dict[str, Any]] = []
    saved_paths: List[str] = []

    try:
        for f in uploaded_files:
            if not f.filename:
                continue

            # Basic size guard (Flask MAX_CONTENT_LENGTH handles globally too)
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
            if size > ALLOWED_MAX_SIZE:
                results.append({
                    "file_name"   : f.filename,
                    "error"       : "File exceeds 256 MB limit",
                    "threat_score": 0,
                    "threat_level": "SKIPPED",
                })
                continue

            path = _save_upload(f)
            saved_paths.append(path)
            result = _scan_single_file(path, f.filename)
            results.append(result)

    finally:
        # Clean up temporary uploads (quarantine keeps copies of threats)
        for p in saved_paths:
            try:
                os.remove(p)
            except OSError:
                pass

    payload = {
        "scan_id"     : scan_id,
        "timestamp"   : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "file_count"  : len(results),
        "results"     : results,
        "summary"     : _build_summary(results),
    }
    _scan_cache[scan_id] = payload
    return jsonify(payload), 200


@scan_bp.route("/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Retrieve a previously cached scan result."""
    result = _scan_cache.get(scan_id)
    if not result:
        return jsonify({"error": "Scan ID not found"}), 404
    return jsonify(result), 200


def _build_summary(results: List[Dict]) -> Dict[str, Any]:
    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "SAFE": 0, "SKIPPED": 0}
    total_threats = 0
    for r in results:
        lvl = r.get("threat_level", "SAFE")
        threat_counts[lvl] = threat_counts.get(lvl, 0) + 1
        if lvl in ("CRITICAL", "HIGH"):
            total_threats += 1

    max_score = max((r.get("threat_score", 0) for r in results), default=0)
    return {
        "total_files"  : len(results),
        "threat_counts": threat_counts,
        "total_threats": total_threats,
        "max_score"    : max_score,
    }
