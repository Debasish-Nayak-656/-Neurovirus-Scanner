"""
VirusTotal v3 API – hash lookup.

Docs: https://developers.virustotal.com/reference/overview
Free tier: 4 requests/min, 500/day.
"""

import logging
import time
from typing import Dict, Any

import requests

logger = logging.getLogger("neurovirus.virustotal")

VT_BASE  = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15   # seconds
_last_call_ts: float = 0.0


def query_virustotal(sha256: str, api_key: str) -> Dict[str, Any]:
    """
    Look up a file hash on VirusTotal.

    Returns:
        {
            "engine"        : "virustotal",
            "available"     : bool,
            "found"         : bool,
            "positives"     : int,
            "total"         : int,
            "permalink"     : str,
            "scan_date"     : str,
            "detections"    : {engine: result, ...},
            "error"         : str | None,
        }
    """
    global _last_call_ts

    result: Dict[str, Any] = {
        "engine"    : "virustotal",
        "available" : False,
        "found"     : False,
        "positives" : 0,
        "total"     : 0,
        "permalink" : "",
        "scan_date" : "",
        "detections": {},
        "error"     : None,
    }

    if not api_key:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        return result

    # Polite rate-limiting: free tier = 4 req/min
    elapsed = time.time() - _last_call_ts
    if elapsed < 15:
        time.sleep(15 - elapsed)

    try:
        _last_call_ts = time.time()
        resp = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )

        if resp.status_code == 404:
            result["available"] = True
            result["found"]     = False
            return result

        if resp.status_code == 401:
            result["error"] = "VirusTotal API key invalid or quota exceeded"
            return result

        resp.raise_for_status()
        result["available"] = True

        data   = resp.json()
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        scans  = attrs.get("last_analysis_results", {})

        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total     = sum(stats.values())

        result["found"]      = True
        result["positives"]  = positives
        result["total"]      = total
        result["scan_date"]  = attrs.get("last_analysis_date", "")
        result["permalink"]  = f"https://www.virustotal.com/gui/file/{sha256}"

        # Only keep engines that flagged the file
        result["detections"] = {
            engine: info.get("result")
            for engine, info in scans.items()
            if info.get("category") in ("malicious", "suspicious")
        }

    except requests.Timeout:
        result["error"] = "VirusTotal request timed out"
    except requests.RequestException as e:
        result["error"] = str(e)
        logger.exception("VirusTotal request failed")

    return result


def submit_file_to_virustotal(file_path: str, api_key: str) -> Dict[str, Any]:
    """
    Upload a new file to VirusTotal for scanning (when hash lookup returns 404).
    Returns the analysis ID and a polling URL.
    """
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}

    try:
        with open(file_path, "rb") as fh:
            resp = requests.post(
                f"{VT_BASE}/files",
                headers={"x-apikey": api_key},
                files={"file": fh},
                timeout=60,
            )
        resp.raise_for_status()
        data = resp.json()
        analysis_id = data.get("data", {}).get("id", "")
        return {
            "analysis_id" : analysis_id,
            "poll_url"    : f"{VT_BASE}/analyses/{analysis_id}",
        }
    except Exception as e:
        return {"error": str(e)}
