"""
ClamAV integration via clamd (TCP socket to clamd daemon).

Install:  pip install clamd
System:   apt-get install clamav clamav-daemon  &&  freshclam
"""

import logging
import socket
from typing import Dict, Any

logger = logging.getLogger("neurovirus.clamav")

try:
    import clamd
    _CLAMD_AVAILABLE = True
except ImportError:
    _CLAMD_AVAILABLE = False
    logger.warning("clamd not installed — ClamAV scanning disabled. pip install clamd")


def ping_clamav(host: str = "127.0.0.1", port: int = 3310) -> bool:
    """Return True if clamd is reachable."""
    if not _CLAMD_AVAILABLE:
        return False
    try:
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=5)
        cd.ping()
        return True
    except Exception:
        return False


def scan_with_clamav(file_path: str, host: str = "127.0.0.1", port: int = 3310) -> Dict[str, Any]:
    """
    Scan a file with ClamAV via clamd TCP socket.

    Returns:
        {
            "engine"    : "clamav",
            "available" : bool,
            "infected"  : bool,
            "virus_name": str | None,
            "raw"       : dict,
            "error"     : str | None,
        }
    """
    result: Dict[str, Any] = {
        "engine"    : "clamav",
        "available" : False,
        "infected"  : False,
        "virus_name": None,
        "raw"       : {},
        "error"     : None,
    }

    if not _CLAMD_AVAILABLE:
        result["error"] = "clamd Python library not installed"
        return result

    try:
        cd = clamd.ClamdNetworkSocket(host=host, port=port, timeout=60)
        cd.ping()
        result["available"] = True

        scan_result = cd.scan(file_path)
        # scan_result example: {'/path/file': ('FOUND', 'Eicar-Test-Signature')}
        if scan_result:
            status, virus = list(scan_result.values())[0]
            if status == "FOUND":
                result["infected"]   = True
                result["virus_name"] = virus
            result["raw"] = scan_result

    except clamd.ConnectionError as e:
        result["error"] = f"Cannot connect to clamd at {host}:{port} — {e}"
        logger.warning(result["error"])
    except Exception as e:
        result["error"] = str(e)
        logger.exception("ClamAV scan error")

    return result
