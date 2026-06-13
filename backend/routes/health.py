"""
/api/health  –  Liveness + readiness probes.
"""

import logging
from flask import Blueprint, jsonify, current_app

from utils.clamav_scanner import ping_clamav

logger    = logging.getLogger("neurovirus.health")
health_bp = Blueprint("health", __name__)


@health_bp.route("/", methods=["GET"])
@health_bp.route("", methods=["GET"])
def health():
    """Quick liveness check."""
    return jsonify({"status": "ok", "service": "neurovirus-backend"}), 200


@health_bp.route("/ready", methods=["GET"])
def readiness():
    """Check all subsystems are available."""
    checks = {}

    # ClamAV
    try:
        ok = ping_clamav(
            host=current_app.config["CLAMAV_HOST"],
            port=current_app.config["CLAMAV_PORT"],
        )
        checks["clamav"] = "ok" if ok else "unavailable"
    except Exception as e:
        checks["clamav"] = f"error: {e}"

    # VirusTotal key configured?
    checks["virustotal_key"] = "configured" if current_app.config.get("VIRUSTOTAL_API_KEY") else "missing"

    # YARA rules directory
    import os
    rules_dir = current_app.config["YARA_RULES_DIR"]
    checks["yara_rules"] = "ok" if os.path.isdir(rules_dir) else "rules dir missing"

    all_ok = checks["clamav"] == "ok"
    return jsonify({"status": "ready" if all_ok else "degraded", "checks": checks}), 200 if all_ok else 207
