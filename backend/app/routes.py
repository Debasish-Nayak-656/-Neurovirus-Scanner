"""
API Routes
  POST /api/scan          - Upload and scan file(s)
  GET  /api/scan/<id>     - Retrieve scan result by ID
  GET  /api/history       - List recent scans
  POST /api/quarantine    - Move file to quarantine
  GET  /api/status        - Engine status (ClamAV / YARA / VT)
  DELETE /api/scan/<id>   - Delete scan result and uploaded file
"""

import os
import uuid
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from .scanner import ScannerEngine

scanner_bp = Blueprint("scanner", __name__)
logger = logging.getLogger(__name__)

# In-memory result store (replace with DB in production)
_scan_results: dict = {}


def _get_engine() -> ScannerEngine:
    if not hasattr(current_app, "_scanner_engine"):
        current_app._scanner_engine = ScannerEngine(current_app.config)
    return current_app._scanner_engine


def _allowed_file(filename: str) -> bool:
    allowed = current_app.config.get("ALLOWED_EXTENSIONS", set())
    if not allowed:
        return True  # Allow all if empty set
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in allowed


# ─── POST /api/scan ───────────────────────────────────────────────────────────
@scanner_bp.route("/scan", methods=["POST"])
def scan_files():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No selected files"}), 400

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    engine = _get_engine()
    results = []

    for file in files:
        if not file or not _allowed_file(file.filename):
            continue

        # Save with unique name to avoid collisions
        original_name = secure_filename(file.filename) or "unknown"
        unique_name = f"{uuid.uuid4().hex}_{original_name}"
        save_path = os.path.join(upload_folder, unique_name)

        try:
            file.save(save_path)
            result = engine.scan(save_path, original_name)
            result_dict = result.to_dict()
            result_dict["_saved_path"] = save_path  # internal use

            _scan_results[result.scan_id] = result_dict
            results.append(result_dict)

            logger.info(f"Scanned {original_name} → score={result.threat_score} level={result.threat_level}")

        except Exception as e:
            logger.exception(f"Failed to scan {file.filename}")
            results.append({
                "filename": file.filename,
                "error": str(e),
                "threat_level": "ERROR",
            })

    return jsonify({
        "scanned": len(results),
        "results": results,
    }), 200


# ─── GET /api/scan/<scan_id> ──────────────────────────────────────────────────
@scanner_bp.route("/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Scan result not found"}), 404
    return jsonify(result), 200


# ─── DELETE /api/scan/<scan_id> ───────────────────────────────────────────────
@scanner_bp.route("/scan/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    result = _scan_results.pop(scan_id, None)
    if not result:
        return jsonify({"error": "Not found"}), 404
    path = result.get("_saved_path")
    if path and os.path.exists(path):
        os.remove(path)
    return jsonify({"deleted": scan_id}), 200


# ─── GET /api/history ─────────────────────────────────────────────────────────
@scanner_bp.route("/history", methods=["GET"])
def get_history():
    limit = int(request.args.get("limit", 50))
    items = list(_scan_results.values())[-limit:]
    # Return lightweight summary
    summary = [
        {
            "scan_id": r["scan_id"],
            "filename": r["filename"],
            "timestamp": r["timestamp"],
            "threat_score": r["threat_score"],
            "threat_level": r["threat_level"],
            "file_size": r["file_size"],
            "finding_count": len(r.get("findings", [])),
        }
        for r in items
    ]
    return jsonify({"total": len(summary), "scans": summary}), 200


# ─── POST /api/quarantine ─────────────────────────────────────────────────────
@scanner_bp.route("/quarantine", methods=["POST"])
def quarantine_file():
    data = request.get_json()
    scan_id = data.get("scan_id") if data else None
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400

    result = _scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404

    src = result.get("_saved_path")
    if not src or not os.path.exists(src):
        return jsonify({"error": "File not found on disk"}), 404

    q_folder = current_app.config["QUARANTINE_FOLDER"]
    os.makedirs(q_folder, exist_ok=True)
    dest = os.path.join(q_folder, os.path.basename(src) + ".quarantine")
    os.rename(src, dest)
    result["_saved_path"] = dest
    result["quarantined"] = True

    return jsonify({"quarantined": True, "scan_id": scan_id}), 200


# ─── GET /api/status ──────────────────────────────────────────────────────────
@scanner_bp.route("/status", methods=["GET"])
def engine_status():
    status = {
        "engine": "NeuroVirus v3.14.1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "clamav": _check_clamav(),
        "yara": _check_yara(),
        "virustotal": _check_virustotal(),
    }
    return jsonify(status), 200


def _check_clamav() -> dict:
    try:
        import clamd
        cd = clamd.ClamdNetworkSocket(
            host=current_app.config.get("CLAMD_HOST", "127.0.0.1"),
            port=int(current_app.config.get("CLAMD_PORT", 3310)),
            timeout=5,
        )
        version = cd.version()
        return {"available": True, "version": version}
    except ImportError:
        return {"available": False, "error": "clamd package not installed"}
    except Exception as e:
        return {"available": False, "error": str(e)}


def _check_yara() -> dict:
    try:
        import yara
        rules_dir = current_app.config.get("YARA_RULES_DIR", "yara_rules")
        rule_files = [f for f in os.listdir(rules_dir) if f.endswith((".yar", ".yara"))] if os.path.isdir(rules_dir) else []
        return {"available": True, "rule_files": len(rule_files), "yara_version": yara.__version__}
    except ImportError:
        return {"available": False, "error": "yara-python not installed"}
    except Exception as e:
        return {"available": False, "error": str(e)}


def _check_virustotal() -> dict:
    api_key = current_app.config.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"available": False, "error": "VIRUSTOTAL_API_KEY not set"}
    return {"available": True, "key_configured": True}
