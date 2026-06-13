"""
YARA rule scanning.

Install:  pip install yara-python
Rules:    Place .yar / .yara files inside  backend/rules/
          Community rules: https://github.com/Yara-Rules/rules
"""

import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger("neurovirus.yara")

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("yara-python not installed — YARA scanning disabled. pip install yara-python")

# Compiled rules cache (recompile only when rules change)
_compiled_rules = None
_rules_mtime    = 0.0


def _load_rules(rules_dir: str):
    """Compile all .yar / .yara files in rules_dir into a single ruleset."""
    global _compiled_rules, _rules_mtime

    if not os.path.isdir(rules_dir):
        logger.warning("YARA rules directory not found: %s", rules_dir)
        return None

    # Gather rule files
    rule_files = {}
    for fname in os.listdir(rules_dir):
        if fname.endswith((".yar", ".yara")):
            namespace = fname.rsplit(".", 1)[0]
            rule_files[namespace] = os.path.join(rules_dir, fname)

    if not rule_files:
        logger.warning("No .yar/.yara files found in %s", rules_dir)
        return None

    # Check if any file changed
    latest_mtime = max(os.path.getmtime(p) for p in rule_files.values())
    if _compiled_rules is not None and latest_mtime <= _rules_mtime:
        return _compiled_rules

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
        _rules_mtime    = latest_mtime
        logger.info("YARA: compiled %d rule files", len(rule_files))
    except yara.SyntaxError as e:
        logger.error("YARA compilation error: %s", e)
        _compiled_rules = None

    return _compiled_rules


def scan_with_yara(file_path: str, rules_dir: str) -> Dict[str, Any]:
    """
    Scan a file with YARA rules.

    Returns:
        {
            "engine"   : "yara",
            "available": bool,
            "matches"  : [str, ...],    # rule names matched
            "details"  : [{...}, ...],  # full match objects
            "error"    : str | None,
        }
    """
    result: Dict[str, Any] = {
        "engine"   : "yara",
        "available": False,
        "matches"  : [],
        "details"  : [],
        "error"    : None,
    }

    if not _YARA_AVAILABLE:
        result["error"] = "yara-python not installed"
        return result

    rules = _load_rules(rules_dir)
    if rules is None:
        result["error"] = "No compiled YARA rules available"
        return result

    result["available"] = True

    try:
        matches = rules.match(file_path, timeout=60)
        for m in matches:
            result["matches"].append(m.rule)
            result["details"].append({
                "rule"     : m.rule,
                "namespace": m.namespace,
                "tags"     : list(m.tags),
                "meta"     : dict(m.meta),
                "strings"  : [
                    {
                        "offset"    : s.instances[0].offset if s.instances else 0,
                        "identifier": s.identifier,
                        "data"      : repr(s.instances[0].matched_data[:64] if s.instances else b""),
                    }
                    for s in m.strings[:5]   # cap at 5 string hits per rule
                ],
            })
    except yara.TimeoutError:
        result["error"] = "YARA scan timed out (>60 s)"
    except Exception as e:
        result["error"] = str(e)
        logger.exception("YARA scan error")

    return result
