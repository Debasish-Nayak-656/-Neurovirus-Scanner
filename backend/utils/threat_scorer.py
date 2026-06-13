"""
Aggregate threat scoring.

Weights all engine outputs into a single 0–100 threat score
and derives a human-readable threat level.
"""

from typing import Dict, Any, Tuple


# ── Threat levels ─────────────────────────────────────────────────────────────
def _score_to_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MODERATE"
    if score >= 10:
        return "LOW"
    return "SAFE"


# ── Individual engine scorers ─────────────────────────────────────────────────

def _score_clamav(clam: Dict) -> int:
    if not clam.get("available"):
        return 0
    if clam.get("infected"):
        virus = clam.get("virus_name", "")
        if "Ransomware" in virus or "Rootkit" in virus:
            return 90
        if "Trojan" in virus or "Backdoor" in virus:
            return 80
        if "Adware" in virus or "PUA" in virus:
            return 35
        return 60
    return 0


def _score_yara(yara: Dict) -> int:
    if not yara.get("available"):
        return 0
    matches = yara.get("matches", [])
    if not matches:
        return 0
    # Each match adds points; diminishing returns
    base = min(85, 25 * len(matches))
    # Boost for known critical categories
    for m in matches:
        m_lower = m.lower()
        if any(k in m_lower for k in ("ransomware", "rootkit", "exploit")):
            base = max(base, 85)
            break
        if any(k in m_lower for k in ("trojan", "backdoor", "rat")):
            base = max(base, 75)
            break
        if any(k in m_lower for k in ("miner", "adware", "pua")):
            base = max(base, 40)
    return base


def _score_virustotal(vt: Dict) -> int:
    if not vt.get("available") or not vt.get("found"):
        return 0
    positives = vt.get("positives", 0)
    total     = vt.get("total", 1)
    ratio     = positives / total if total else 0
    if ratio == 0:
        return 0
    if ratio >= 0.5:
        return 95
    if ratio >= 0.3:
        return 80
    if ratio >= 0.1:
        return 55
    if positives >= 3:
        return 40
    return 20


def _score_entropy(entropy: Dict) -> int:
    if entropy.get("is_packed"):
        return 30
    overall = entropy.get("overall", 0)
    if overall >= 7.5:
        return 25
    if overall >= 7.0:
        return 15
    return 0


def _score_network(network: Dict) -> int:
    return min(60, network.get("network_risk_score", 0))


def _score_metadata(meta: Dict) -> int:
    score = 0
    if meta.get("extension_mismatch"):
        score += 25
    risk = meta.get("risk_level", "UNKNOWN")
    if risk == "HIGH":
        score += 10
    # Suspicious PE imports
    pe = meta.get("pe_info", {})
    sus_imports = pe.get("suspicious_imports", [])
    score += min(30, len(sus_imports) * 6)
    return min(50, score)


# ── Master scorer ─────────────────────────────────────────────────────────────

def compute_threat_score(
    clam: Dict,
    yara: Dict,
    vt: Dict,
    entropy: Dict,
    network: Dict,
    meta: Dict,
) -> Tuple[int, str]:
    """
    Combine all engine scores into one threat score (0–100).

    Strategy:
      - If any definitive engine (ClamAV, VT) gives a high score → that dominates.
      - Otherwise accumulate weighted contributions.
    """
    s_clam     = _score_clamav(clam)
    s_yara     = _score_yara(yara)
    s_vt       = _score_virustotal(vt)
    s_entropy  = _score_entropy(entropy)
    s_network  = _score_network(network)
    s_meta     = _score_metadata(meta)

    # Definitive detections dominate
    definitive = max(s_clam, s_yara, s_vt)

    # Heuristic accumulation (weighted sum, capped)
    heuristic = int(
        s_entropy * 0.4
        + s_network * 0.4
        + s_meta    * 0.2
    )
    heuristic = min(50, heuristic)   # heuristics alone can't exceed 50

    # Combine
    if definitive >= 60:
        # High-confidence detection: blend in small heuristic boost
        final = min(100, definitive + heuristic // 5)
    else:
        final = min(100, definitive + heuristic)

    return final, _score_to_level(final)
