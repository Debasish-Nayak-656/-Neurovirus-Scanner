"""
NeuroVirus Scanner Engine
Performs multi-layer file analysis:
  1. File metadata & magic bytes
  2. Entropy analysis
  3. ClamAV signature scan
  4. YARA rule matching
  5. VirusTotal hash lookup (+ upload if small)
  6. Suspicious string extraction
  7. PE header analysis (executables)
  8. Network indicator extraction
"""

import os
import math
import hashlib
import struct
import re
import json
import time
import logging
from datetime import datetime
from typing import Optional
import requests

logger = logging.getLogger(__name__)

# ─── Magic bytes map ──────────────────────────────────────────────────────────
MAGIC_SIGNATURES = {
    b"\x4d\x5a":                          ("PE Executable",      "exe"),
    b"\x7f\x45\x4c\x46":                  ("ELF Binary",         "elf"),
    b"\x25\x50\x44\x46":                  ("PDF Document",       "pdf"),
    b"\x50\x4b\x03\x04":                  ("ZIP Archive",        "zip"),
    b"\x52\x61\x72\x21\x1a\x07":         ("RAR Archive",        "rar"),
    b"\x1f\x8b":                           ("GZIP Archive",       "gz"),
    b"\xca\xfe\xba\xbe":                  ("Java Class / Mach-O","class"),
    b"\xfe\xed\xfa\xce":                  ("Mach-O 32-bit",      "macho"),
    b"\xfe\xed\xfa\xcf":                  ("Mach-O 64-bit",      "macho"),
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": ("PNG Image",          "png"),
    b"\xff\xd8\xff":                       ("JPEG Image",         "jpg"),
    b"\x47\x49\x46\x38":                  ("GIF Image",          "gif"),
    b"\x42\x4d":                           ("Bitmap Image",       "bmp"),
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": ("MS Office (OLE2)",   "doc"),
    b"\x4d\x53\x43\x46":                  ("MS Cabinet",         "cab"),
    b"\x37\x7a\xbc\xaf\x27\x1c":         ("7-Zip Archive",      "7z"),
    b"\x75\x73\x74\x61\x72":             ("TAR Archive",        "tar"),
    b"\x23\x21":                           ("Script/Shebang",     "sh"),
}

# ─── Risky extensions ─────────────────────────────────────────────────────────
RISKY_EXTENSIONS = {
    "exe","dll","bat","cmd","vbs","vbe","js","jse","wsf","wsh",
    "ps1","ps2","psc1","psc2","com","pif","scr","hta","cpl",
    "jar","apk","dex","msi","msp","reg","lnk","inf","sys","drv",
}
SUSPICIOUS_EXTENSIONS = {
    "doc","docm","xls","xlsm","ppt","pptm","pdf","zip","rar",
    "7z","iso","img","dmg","tar","gz","bz2","sh","py","rb","pl",
}

# ─── Suspicious strings patterns ──────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    (r"(?i)cmd\.exe",                        "CMD shell reference",         "medium"),
    (r"(?i)powershell",                      "PowerShell reference",        "medium"),
    (r"(?i)WScript\.Shell",                  "WScript Shell usage",         "high"),
    (r"(?i)CreateObject",                    "COM object creation",         "medium"),
    (r"(?i)(wget|curl)\s+https?://",         "Remote download command",     "high"),
    (r"(?i)base64",                          "Base64 encoding detected",    "medium"),
    (r"(?i)eval\(",                          "eval() call (obfuscation)",   "high"),
    (r"(?i)exec\(",                          "exec() call",                 "medium"),
    (r"(?i)ShellExecute",                    "ShellExecute API",            "high"),
    (r"(?i)VirtualAlloc",                    "Memory allocation (inject)",  "high"),
    (r"(?i)WriteProcessMemory",              "Process injection API",       "critical"),
    (r"(?i)CreateRemoteThread",              "Remote thread injection",     "critical"),
    (r"(?i)IsDebuggerPresent",              "Anti-debug technique",        "high"),
    (r"(?i)RegOpenKey",                     "Registry access",             "medium"),
    (r"(?i)HKEY_LOCAL_MACHINE.*Run",        "Startup registry key",        "high"),
    (r"(?i)net\.exe.*(user|localgroup)",    "User account manipulation",   "high"),
    (r"(?i)icacls|cacls|attrib\s+\+[hsr]", "Permission manipulation",     "medium"),
    (r"(?i)taskkill.*antivirus",            "AV process kill attempt",     "critical"),
    (r"(?i)shadow\s*copy|vssadmin",         "Shadow copy deletion",        "critical"),
    (r"(?i)\.onion",                        "Tor hidden service URL",      "high"),
    (r"stratum\+tcp://",                    "Crypto miner stratum URL",    "high"),
    (r"(?i)(mimikatz|sekurlsa|lsadump)",    "Credential dumping tool",     "critical"),
    (r"(?i)nc\.exe|netcat",                "Netcat reverse shell",        "critical"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}", "IP:Port hardcoded","medium"),
]

# ─── PE section names that are suspicious ─────────────────────────────────────
SUSPICIOUS_PE_SECTIONS = {".packed", ".crypted", ".encrypt", "UPX0", "UPX1", ".themida", ".aspack"}


class ScanResult:
    def __init__(self, filename: str, filepath: str):
        self.filename = filename
        self.filepath = filepath
        self.scan_id = hashlib.md5(f"{filename}{time.time()}".encode()).hexdigest()[:12]
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.file_size = 0
        self.file_type_magic = "Unknown"
        self.file_extension = ""
        self.mime_type = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.entropy = 0.0
        self.threat_score = 0          # 0-100
        self.threat_level = "SAFE"     # SAFE / LOW / MODERATE / HIGH / CRITICAL
        self.findings = []             # list of Finding dicts
        self.clamav_result = None
        self.yara_matches = []
        self.virustotal = None
        self.suspicious_strings = []
        self.network_indicators = []
        self.pe_info = None
        self.scan_duration_ms = 0
        self.errors = []

    def add_finding(self, name: str, detail: str, severity: str, category: str):
        self.findings.append({
            "name": name,
            "detail": detail,
            "severity": severity,        # clean / info / low / medium / high / critical
            "category": category,        # MALWARE / NETWORK / FILETYPE / BEHAVIOR / YARA / HEURISTIC
        })
        # Update threat score
        score_map = {"critical": 40, "high": 25, "medium": 15, "low": 8, "info": 2, "clean": 0}
        self.threat_score = min(100, self.threat_score + score_map.get(severity, 0))

    def finalize(self):
        if self.threat_score >= 75:
            self.threat_level = "CRITICAL"
        elif self.threat_score >= 50:
            self.threat_level = "HIGH"
        elif self.threat_score >= 25:
            self.threat_level = "MODERATE"
        elif self.threat_score > 0:
            self.threat_level = "LOW"
        else:
            self.threat_level = "SAFE"

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "filename": self.filename,
            "file_size": self.file_size,
            "file_type_magic": self.file_type_magic,
            "file_extension": self.file_extension,
            "mime_type": self.mime_type,
            "hashes": {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256},
            "entropy": round(self.entropy, 4),
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "findings": self.findings,
            "clamav": self.clamav_result,
            "yara_matches": self.yara_matches,
            "virustotal": self.virustotal,
            "suspicious_strings": self.suspicious_strings,
            "network_indicators": self.network_indicators,
            "pe_info": self.pe_info,
            "scan_duration_ms": self.scan_duration_ms,
            "errors": self.errors,
        }


class ScannerEngine:
    def __init__(self, config):
        self.config = config
        self._yara_rules = None
        self._load_yara()

    def _load_yara(self):
        try:
            import yara
            rules_dir = self.config.get("YARA_RULES_DIR", "yara_rules")
            if os.path.isdir(rules_dir):
                rule_files = {}
                for fname in os.listdir(rules_dir):
                    if fname.endswith((".yar", ".yara")):
                        ns = fname.replace(".", "_")
                        rule_files[ns] = os.path.join(rules_dir, fname)
                if rule_files:
                    self._yara_rules = yara.compile(filepaths=rule_files)
                    logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except ImportError:
            logger.warning("yara-python not installed — YARA scanning disabled")
        except Exception as e:
            logger.warning(f"YARA load error: {e}")

    # ─── Main entry ───────────────────────────────────────────────────────────
    def scan(self, filepath: str, filename: str) -> ScanResult:
        t0 = time.time()
        result = ScanResult(filename, filepath)

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            result.file_size = len(data)
            result.file_extension = os.path.splitext(filename)[1].lstrip(".").lower()

            self._analyze_metadata(result, data)
            self._analyze_entropy(result, data)
            self._analyze_strings(result, data)
            self._analyze_network_indicators(result, data)
            self._analyze_pe(result, data)
            self._scan_clamav(result, filepath)
            self._scan_yara(result, data)
            self._lookup_virustotal(result)
            self._assess_file_type_risk(result)

            if not result.findings:
                result.add_finding("No threats detected", f"{filename} passed all scan checks.", "clean", "CLEAN")

        except Exception as e:
            result.errors.append(str(e))
            logger.exception(f"Scan error for {filename}")

        result.scan_duration_ms = int((time.time() - t0) * 1000)
        result.finalize()
        return result

    # ─── 1. Metadata & hashes ─────────────────────────────────────────────────
    def _analyze_metadata(self, result: ScanResult, data: bytes):
        result.md5    = hashlib.md5(data).hexdigest()
        result.sha1   = hashlib.sha1(data).hexdigest()
        result.sha256 = hashlib.sha256(data).hexdigest()

        # Detect magic
        for magic, (ftype, ext) in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                result.file_type_magic = ftype
                break
        else:
            # Fallback: check if text
            try:
                data[:512].decode("utf-8")
                result.file_type_magic = "Text/Script"
            except UnicodeDecodeError:
                result.file_type_magic = "Binary (Unknown)"

    # ─── 2. Shannon entropy ───────────────────────────────────────────────────
    def _analyze_entropy(self, result: ScanResult, data: bytes):
        if not data:
            return
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq if c)
        result.entropy = entropy

        if entropy >= self.config.get("ENTROPY_THRESHOLD", 7.0):
            result.add_finding(
                "High Entropy Detected",
                f"Shannon entropy {entropy:.2f}/8.0 — file may be packed, encrypted, or compressed.",
                "high",
                "HEURISTIC",
            )
        elif entropy >= 6.5:
            result.add_finding(
                "Elevated Entropy",
                f"Shannon entropy {entropy:.2f}/8.0 — possible compression or obfuscation.",
                "medium",
                "HEURISTIC",
            )

    # ─── 3. Suspicious strings ────────────────────────────────────────────────
    def _analyze_strings(self, result: ScanResult, data: bytes):
        # Extract printable strings (min 6 chars)
        printable = re.findall(rb"[ -~]{6,}", data)
        text = b"\n".join(printable).decode("ascii", errors="ignore")

        found_patterns = set()
        for pattern, desc, severity in SUSPICIOUS_PATTERNS:
            if re.search(pattern, text) and desc not in found_patterns:
                found_patterns.add(desc)
                result.suspicious_strings.append({"description": desc, "severity": severity})
                result.add_finding(desc, f"Pattern matched: {pattern}", severity, "BEHAVIOR")

    # ─── 4. Network indicators ────────────────────────────────────────────────
    def _analyze_network_indicators(self, result: ScanResult, data: bytes):
        text = data.decode("ascii", errors="ignore")

        # URLs
        urls = re.findall(r"https?://[^\s\"'<>]{8,}", text)
        # IPs
        ips  = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        # Domains (rough)
        domains = re.findall(r"\b[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:onion|tk|top|xyz|ru|cn|cc)\b", text, re.I)

        indicators = []
        for url in set(urls[:10]):
            severity = "high" if any(x in url for x in [".onion", "pastebin", "ngrok", "bit.ly"]) else "info"
            indicators.append({"type": "URL", "value": url, "severity": severity})
            if severity == "high":
                result.add_finding("Suspicious URL", url, "high", "NETWORK")

        for ip in set(ips[:10]):
            parts = list(map(int, ip.split(".")))
            # Skip private/loopback
            if parts[0] not in (10, 127, 169, 172, 192):
                indicators.append({"type": "IP", "value": ip, "severity": "medium"})

        for domain in set(domains[:10]):
            indicators.append({"type": "DOMAIN", "value": domain, "severity": "high"})
            result.add_finding("Suspicious Domain (TLD)", domain, "high", "NETWORK")

        result.network_indicators = indicators

    # ─── 5. PE header analysis ────────────────────────────────────────────────
    def _analyze_pe(self, result: ScanResult, data: bytes):
        if not data[:2] == b"MZ":
            return
        try:
            # e_lfanew offset at 0x3c
            if len(data) < 0x40:
                return
            pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
            if pe_offset + 24 > len(data):
                return
            sig = data[pe_offset:pe_offset+4]
            if sig != b"PE\x00\x00":
                return

            machine = struct.unpack_from("<H", data, pe_offset+4)[0]
            num_sections = struct.unpack_from("<H", data, pe_offset+6)[0]
            timestamp = struct.unpack_from("<I", data, pe_offset+8)[0]
            characteristics = struct.unpack_from("<H", data, pe_offset+22)[0]

            arch_map = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1c0: "ARM", 0xaa64: "ARM64"}
            arch = arch_map.get(machine, f"Unknown (0x{machine:04x})")

            # Optional header
            opt_offset = pe_offset + 24
            magic = struct.unpack_from("<H", data, opt_offset)[0]
            is_64 = magic == 0x20b

            # Section headers
            opt_size = struct.unpack_from("<H", data, pe_offset+20)[0]
            sect_offset = opt_offset + opt_size
            sections = []
            suspicious_sects = []
            for i in range(min(num_sections, 32)):
                so = sect_offset + i * 40
                if so + 40 > len(data):
                    break
                name = data[so:so+8].rstrip(b"\x00").decode("ascii", errors="replace")
                vsize = struct.unpack_from("<I", data, so+8)[0]
                rsize = struct.unpack_from("<I", data, so+16)[0]
                chars = struct.unpack_from("<I", data, so+36)[0]
                writable = bool(chars & 0x80000000)
                executable = bool(chars & 0x20000000)
                sections.append({"name": name, "virtual_size": vsize, "raw_size": rsize,
                                  "writable": writable, "executable": executable})
                if name in SUSPICIOUS_PE_SECTIONS:
                    suspicious_sects.append(name)
                if writable and executable:
                    result.add_finding("WX Section", f"Section '{name}' is both Writable & Executable (shellcode risk)", "high", "HEURISTIC")

            result.pe_info = {
                "architecture": arch,
                "num_sections": num_sections,
                "compile_timestamp": datetime.utcfromtimestamp(timestamp).isoformat() if timestamp else None,
                "is_64bit": is_64,
                "characteristics": f"0x{characteristics:04x}",
                "sections": sections[:16],
            }

            if suspicious_sects:
                result.add_finding(
                    "Packer/Protector Detected",
                    f"Suspicious section names: {', '.join(suspicious_sects)}",
                    "high", "HEURISTIC",
                )

        except Exception as e:
            result.errors.append(f"PE parse error: {e}")

    # ─── 6. ClamAV ────────────────────────────────────────────────────────────
    def _scan_clamav(self, result: ScanResult, filepath: str):
        try:
            import clamd
            cd = clamd.ClamdNetworkSocket(
                host=self.config.get("CLAMD_HOST", "127.0.0.1"),
                port=int(self.config.get("CLAMD_PORT", 3310)),
                timeout=30,
            )
            scan_result = cd.scan(filepath)
            if scan_result:
                status, virus = next(iter(scan_result.values()))
                result.clamav_result = {"status": status, "signature": virus}
                if status == "FOUND":
                    result.add_finding(
                        f"ClamAV: {virus}",
                        f"ClamAV signature match: {virus}",
                        "critical", "MALWARE",
                    )
            else:
                result.clamav_result = {"status": "OK", "signature": None}
        except ImportError:
            result.clamav_result = {"status": "UNAVAILABLE", "error": "clamd not installed"}
            result.errors.append("ClamAV: clamd Python package not installed")
        except Exception as e:
            result.clamav_result = {"status": "ERROR", "error": str(e)}
            result.errors.append(f"ClamAV connection failed: {e}")

    # ─── 7. YARA ──────────────────────────────────────────────────────────────
    def _scan_yara(self, result: ScanResult, data: bytes):
        if not self._yara_rules:
            return
        try:
            matches = self._yara_rules.match(data=data)
            for m in matches:
                result.yara_matches.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                })
                severity = m.meta.get("severity", "high")
                description = m.meta.get("description", m.rule)
                result.add_finding(
                    f"YARA: {m.rule}",
                    description,
                    severity, "YARA",
                )
        except Exception as e:
            result.errors.append(f"YARA scan error: {e}")

    # ─── 8. VirusTotal ────────────────────────────────────────────────────────
    def _lookup_virustotal(self, result: ScanResult):
        api_key = self.config.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            result.virustotal = {"status": "NO_API_KEY"}
            return

        base_url = self.config.get("VIRUSTOTAL_API_URL", "https://www.virustotal.com/api/v3")
        headers = {"x-apikey": api_key}

        try:
            # 1. Hash lookup first (fast, free)
            resp = requests.get(
                f"{base_url}/files/{result.sha256}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                vt_data = resp.json()["data"]["attributes"]
                stats = vt_data.get("last_analysis_stats", {})
                result.virustotal = {
                    "status": "FOUND",
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "stats": stats,
                    "names": vt_data.get("meaningful_name", ""),
                    "type_description": vt_data.get("type_description", ""),
                    "first_seen": vt_data.get("first_submission_date"),
                    "last_seen": vt_data.get("last_analysis_date"),
                    "link": f"https://www.virustotal.com/gui/file/{result.sha256}",
                }
                malicious = stats.get("malicious", 0)
                if malicious >= 10:
                    result.add_finding(
                        f"VirusTotal: {malicious} engines flagged",
                        f"{malicious}/{sum(stats.values())} AV engines detected this as malicious",
                        "critical", "MALWARE",
                    )
                elif malicious >= 3:
                    result.add_finding(
                        f"VirusTotal: {malicious} engines flagged",
                        f"{malicious}/{sum(stats.values())} AV engines detected suspicious activity",
                        "high", "MALWARE",
                    )
                elif malicious >= 1:
                    result.add_finding(
                        f"VirusTotal: {malicious} engine flagged",
                        f"{malicious}/{sum(stats.values())} AV engine detected suspicious activity",
                        "medium", "MALWARE",
                    )
                return

            # 2. If not found and file is small enough, upload it
            if resp.status_code == 404 and result.file_size < self.config.get("MAX_FILE_SIZE_VIRUSTOTAL", 32*1024*1024):
                with open(result.filepath, "rb") as f:
                    upload_resp = requests.post(
                        f"{base_url}/files",
                        headers=headers,
                        files={"file": (result.filename, f)},
                        timeout=60,
                    )
                if upload_resp.status_code == 200:
                    analysis_id = upload_resp.json()["data"]["id"]
                    result.virustotal = {
                        "status": "SUBMITTED",
                        "analysis_id": analysis_id,
                        "link": f"https://www.virustotal.com/gui/file/{result.sha256}",
                        "message": "File submitted to VirusTotal. Check results in ~60 seconds.",
                    }
                    # Poll once after short delay
                    time.sleep(15)
                    poll = requests.get(
                        f"{base_url}/analyses/{analysis_id}",
                        headers=headers, timeout=15,
                    )
                    if poll.status_code == 200:
                        pdata = poll.json()["data"]["attributes"]
                        if pdata["status"] == "completed":
                            stats = pdata["stats"]
                            result.virustotal["status"] = "FOUND"
                            result.virustotal["detections"] = stats.get("malicious", 0)
                            result.virustotal["total_engines"] = sum(stats.values())
                            result.virustotal["stats"] = stats
                else:
                    result.virustotal = {"status": "UPLOAD_FAILED", "error": upload_resp.text[:200]}
            else:
                result.virustotal = {"status": "NOT_FOUND", "sha256": result.sha256}

        except requests.exceptions.RequestException as e:
            result.virustotal = {"status": "ERROR", "error": str(e)}
            result.errors.append(f"VirusTotal API error: {e}")

    # ─── 9. File type risk ────────────────────────────────────────────────────
    def _assess_file_type_risk(self, result: ScanResult):
        ext = result.file_extension.lower()
        if ext in RISKY_EXTENSIONS:
            result.add_finding(
                f"High-Risk File Type (.{ext})",
                f"Extension '.{ext}' is commonly used to deliver malware or execute code.",
                "medium", "FILETYPE",
            )
        elif ext in SUSPICIOUS_EXTENSIONS:
            result.add_finding(
                f"Potentially Risky File Type (.{ext})",
                f"Extension '.{ext}' can contain macros or embedded code.",
                "low", "FILETYPE",
            )

        # Magic vs extension mismatch
        magic_type = result.file_type_magic.lower()
        if ext == "pdf" and "pdf" not in magic_type:
            result.add_finding(
                "File Extension Mismatch",
                f"Extension says .pdf but magic bytes indicate: {result.file_type_magic}",
                "high", "FILETYPE",
            )
        elif ext in ("jpg", "jpeg") and "jpeg" not in magic_type:
            if "pe executable" in magic_type or "elf" in magic_type:
                result.add_finding(
                    "File Extension Mismatch (Disguised Executable)",
                    f"File disguised as image but is actually: {result.file_type_magic}",
                    "critical", "FILETYPE",
                )
