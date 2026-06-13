"""
Shannon entropy analysis.

High entropy (> 7.0) in file sections indicates:
  - Packing (UPX, etc.)
  - Encryption
  - Obfuscation

We analyse:
  1. Overall file entropy
  2. Sliding-window entropy of 4KB blocks to find local high-entropy regions
"""

import math
import logging
from typing import Dict, Any, List

logger = logging.getLogger("neurovirus.entropy")

BLOCK_SIZE       = 4096
HIGH_ENTROPY_THR = 7.0    # bits/byte  (max = 8.0)
VERY_HIGH_THR    = 7.5


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def calculate_entropy(file_path: str) -> Dict[str, Any]:
    """
    Analyse file entropy across the whole file and in sliding blocks.

    Returns:
        {
            "overall"          : float,       # 0–8 bits/byte
            "is_packed"        : bool,
            "high_entropy_regions": int,      # count of 4KB blocks with H > 7.0
            "blocks"           : [float],     # per-block entropies (max 128)
            "verdict"          : str,
        }
    """
    result: Dict[str, Any] = {
        "overall"              : 0.0,
        "is_packed"            : False,
        "high_entropy_regions" : 0,
        "blocks"               : [],
        "verdict"              : "normal",
    }

    try:
        with open(file_path, "rb") as fh:
            data = fh.read()

        if not data:
            return result

        result["overall"] = round(_shannon_entropy(data), 4)

        # Sliding-window analysis
        blocks: List[float] = []
        high_count = 0
        for i in range(0, len(data), BLOCK_SIZE):
            chunk = data[i: i + BLOCK_SIZE]
            h     = _shannon_entropy(chunk)
            blocks.append(round(h, 3))
            if h >= HIGH_ENTROPY_THR:
                high_count += 1

        result["blocks"]               = blocks[:128]   # cap for response size
        result["high_entropy_regions"] = high_count

        overall = result["overall"]
        if overall >= VERY_HIGH_THR or high_count >= max(1, len(blocks) // 4):
            result["is_packed"] = True
            result["verdict"]   = "LIKELY PACKED/ENCRYPTED"
        elif overall >= HIGH_ENTROPY_THR:
            result["verdict"]   = "HIGH ENTROPY — possibly compressed"
        elif overall >= 6.0:
            result["verdict"]   = "moderate entropy"
        else:
            result["verdict"]   = "normal"

    except Exception as e:
        result["error"] = str(e)
        logger.exception("Entropy calculation failed")

    return result
