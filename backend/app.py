"""
NeuroVirus - Advanced Threat Intelligence Platform
Backend: Flask + ClamAV + YARA + VirusTotal API
"""

import os
import logging
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from routes.scan import scan_bp
from routes.report import report_bp
from routes.health import health_bp

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("neurovirus")

# ── App factory ──────────────────────────────────────────────────────────────
def create_app() -> Flask:
    app = Flask(__name__)

    # Config
    app.config.update(
        MAX_CONTENT_LENGTH   = 256 * 1024 * 1024,   # 256 MB upload limit
        UPLOAD_FOLDER        = os.getenv("UPLOAD_DIR", "/tmp/neurovirus_uploads"),
        VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", ""),
        CLAMAV_HOST          = os.getenv("CLAMAV_HOST", "127.0.0.1"),
        CLAMAV_PORT          = int(os.getenv("CLAMAV_PORT", 3310)),
        YARA_RULES_DIR       = os.getenv("YARA_RULES_DIR", "./rules"),
        MAX_FILE_SIZE_BYTES  = 256 * 1024 * 1024,
        QUARANTINE_DIR       = os.getenv("QUARANTINE_DIR", "/tmp/neurovirus_quarantine"),
        SECRET_KEY           = os.getenv("SECRET_KEY", "dev-secret-change-in-prod"),
    )

    # Ensure directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"],   exist_ok=True)
    os.makedirs(app.config["QUARANTINE_DIR"],  exist_ok=True)

    # Extensions
    CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per hour", "30 per minute"],
        storage_uri="memory://",
    )

    # Blueprints
    app.register_blueprint(scan_bp,   url_prefix="/api/scan")
    app.register_blueprint(report_bp, url_prefix="/api/report")
    app.register_blueprint(health_bp, url_prefix="/api/health")

    logger.info("NeuroVirus backend initialised")
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")
