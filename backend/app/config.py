import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "neurovirus-secret-key-change-in-production")

    # Upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "uploads")
    QUARANTINE_FOLDER = os.path.join(os.path.dirname(__file__), "..", "quarantine")
    MAX_CONTENT_LENGTH = 512 * 1024 * 1024  # 512 MB max upload

    # VirusTotal
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

    # ClamAV
    CLAMD_HOST = os.environ.get("CLAMD_HOST", "127.0.0.1")
    CLAMD_PORT = int(os.environ.get("CLAMD_PORT", 3310))

    # YARA rules directory
    YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "yara_rules")

    # Allowed extensions (empty = allow all)
    ALLOWED_EXTENSIONS = set()

    # Scan settings
    ENTROPY_THRESHOLD = 7.0           # Flag high-entropy (packed/encrypted) if above this
    MAX_FILE_SIZE_VIRUSTOTAL = 32 * 1024 * 1024   # 32 MB VT free-tier limit
