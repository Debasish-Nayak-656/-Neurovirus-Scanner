"""
Static network-indicator extraction from binary/text files.

Extracts and classifies:
  - IPv4 / IPv6 addresses
  - Domains / URLs
  - Known C2 ports
  - Suspicious protocol strings (IRC, Tor, P2P)
  - Cryptocurrency wallet addresses
  - Base64-encoded network artefacts
  - Known malicious patterns (DGA-like domains, onion addresses)
"""

import re
import logging
import socket
from typing import Dict, Any, List, Set

logger = logging.getLogger("neurovirus.network")

# ── Regex patterns ─────────────────────────────────────────────────────────────
RE_IPV4      = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_URL       = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,256}", re.IGNORECASE)
RE_DOMAIN    = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cc|ru|xyz|top|tk|ml|ga|cf|gq|pw|onion)\b", re.IGNORECASE)
RE_ONION     = re.compile(rb"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
RE_PORT_HIGH = re.compile(rb"(?:port|PORT|:\\s*)(\d{4,5})")
RE_IRC       = re.compile(rb"(?:irc\.|ircd|PRIVMSG|NICK |PASS |JOIN #)", re.IGNORECASE)
RE_STRATUM   = re.compile(rb"stratum\+tcp://", re.IGNORECASE)
RE_BASE64    = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})")
RE_BTC       = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_ETH       = re.compile(rb"\b0x[0-9a-fA-F]{40}\b")
RE_EMAIL     = re.compile(rb"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,6}\b")

# Known suspicious / C2 ports
SUSPICIOUS_PORTS: Set[int] = {
    4444, 4445, 1337, 31337, 6667, 6668, 6669,   # Metasploit, IRC
    8080, 8888, 9999, 12345, 54321,               # Common backdoors
    1080,                                          # SOCKS proxy
    9050, 9150,                                    # Tor
    3128, 8118,                                    # Squid / Privoxy
}

# Private / reserved IPv4 ranges (not suspicious when internal)
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                    "192.168.", "127.", "0.", "169.254.", "255.")


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _dga_score(domain: str) -> float:
    """Heuristic DGA likelihood: high consonant ratio, long random-looking label."""
    import math
    label = domain.split(".")[0].lower()
    if len(label) < 8:
        return 0.0
    vowels     = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")
    ratio      = consonants / max(1, vowels + consonants)
    # Bigram entropy (higher = more random)
    bigrams = [label[i:i+2] for i in range(len(label)-1)]
    unique  = len(set(bigrams))
    entropy = unique / max(1, len(bigrams))
    return (ratio * 0.6 + entropy * 0.4)


def analyze_network_patterns(file_path: str, max_bytes: int = 5 * 1024 * 1024) -> Dict[str, Any]:
    """
    Extract and classify network indicators from file content.
    Reads at most `max_bytes` to keep analysis fast on large files.

    Returns:
        {
            "ipv4_addresses"      : [str],
            "urls"                : [str],
            "domains"             : [str],
            "onion_addresses"     : [str],
            "suspicious_ports"    : [int],
            "irc_patterns"        : bool,
            "stratum_mining"      : bool,
            "crypto_wallets"      : [str],
            "suspicious_emails"   : [str],
            "dga_candidates"      : [str],
            "risk_indicators"     : [str],   # human-readable findings
            "network_risk_score"  : int,     # 0–100
        }
    """
    result: Dict[str, Any] = {
        "ipv4_addresses"     : [],
        "urls"               : [],
        "domains"            : [],
        "onion_addresses"    : [],
        "suspicious_ports"   : [],
        "irc_patterns"       : False,
        "stratum_mining"     : False,
        "crypto_wallets"     : [],
        "suspicious_emails"  : [],
        "dga_candidates"     : [],
        "risk_indicators"    : [],
        "network_risk_score" : 0,
    }

    try:
        with open(file_path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError as e:
        result["error"] = str(e)
        return result

    # ── Extract raw indicators ─────────────────────────────────────────────
    # IPv4
    ips = list({m.decode() for m in RE_IPV4.findall(data)})
    public_ips = [ip for ip in ips if not _is_private_ip(ip)]
    result["ipv4_addresses"] = public_ips[:30]

    # URLs
    urls = list({m.decode(errors="replace") for m in RE_URL.findall(data)})
    result["urls"] = urls[:30]

    # Domains
    domains = list({m.decode(errors="replace").lower() for m in RE_DOMAIN.findall(data)})
    result["domains"] = domains[:30]

    # Onion
    onions = list({m.decode(errors="replace") for m in RE_ONION.findall(data)})
    result["onion_addresses"] = onions[:10]

    # IRC
    result["irc_patterns"] = bool(RE_IRC.search(data))

    # Stratum (crypto mining)
    result["stratum_mining"] = bool(RE_STRATUM.search(data))

    # Crypto wallets
    btc = [m.decode() for m in RE_BTC.findall(data)]
    eth = [m.decode() for m in RE_ETH.findall(data)]
    result["crypto_wallets"] = list(set(btc + eth))[:10]

    # Emails
    emails = list({m.decode(errors="replace") for m in RE_EMAIL.findall(data)})
    result["suspicious_emails"] = emails[:10]

    # DGA candidates
    dga = [d for d in domains if _dga_score(d) > 0.65]
    result["dga_candidates"] = dga[:10]

    # Port extraction
    port_hits = RE_PORT_HIGH.findall(data)
    sus_ports = list({int(p) for p in port_hits if p.isdigit() and int(p) in SUSPICIOUS_PORTS})
    result["suspicious_ports"] = sus_ports

    # ── Build risk indicators & score ─────────────────────────────────────
    indicators: List[str] = []
    score = 0

    if onions:
        indicators.append(f"Tor .onion address found: {onions[0]}")
        score += 35
    if result["stratum_mining"]:
        indicators.append("Cryptocurrency mining stratum+tcp protocol detected")
        score += 40
    if result["irc_patterns"]:
        indicators.append("IRC botnet command patterns found")
        score += 30
    if public_ips:
        indicators.append(f"{len(public_ips)} public IP address(es) embedded")
        score += min(20, len(public_ips) * 5)
    if urls:
        indicators.append(f"{len(urls)} embedded URL(s) found")
        score += min(15, len(urls) * 3)
    if sus_ports:
        indicators.append(f"Suspicious port(s) referenced: {sus_ports}")
        score += min(25, len(sus_ports) * 8)
    if dga:
        indicators.append(f"DGA-like domain(s) detected: {dga[:3]}")
        score += 25
    if result["crypto_wallets"]:
        indicators.append(f"Cryptocurrency wallet address(es) found")
        score += 15

    result["risk_indicators"]   = indicators
    result["network_risk_score"] = min(100, score)

    return result
