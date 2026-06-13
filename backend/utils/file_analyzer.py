"""
Static file-metadata analysis:
  - Magic bytes / true MIME type (via python-magic)
  - PE header parsing (via pefile)
  - Extension mismatch detection
  - Embedded file detection
  - File type risk classification
"""

import os
import logging
import struct
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger("neurovirus.file_analyzer")

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    import magic as libmagic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False

# ── Risk classification ───────────────────────────────────────────────────────
HIGH_RISK_EXTS = {
    "exe", "dll", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "ps1", "psm1", "psd1", "msi", "msp", "scr", "com", "pif",
    "hta", "cpl", "inf", "reg", "jar", "apk", "dex",
}
MEDIUM_RISK_EXTS = {
    "doc", "docm", "xls", "xlsm", "ppt", "pptm",
    "pdf", "zip", "rar", "7z", "tar", "gz", "iso", "img", "dmg",
    "lnk", "url", "htm", "html", "svg",
}
LOW_RISK_EXTS = {
    "py", "rb", "php", "sh", "bash", "pl", "lua",
    "txt", "csv", "json", "xml", "yaml", "yml",
}

# Known magic-byte signatures
MAGIC_SIGS = {
    b"MZ"                     : "PE Executable (Windows)",
    b"\x7fELF"                : "ELF Executable (Linux)",
    b"\xfe\xed\xfa\xce"       : "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf"       : "Mach-O 64-bit",
    b"\xca\xfe\xba\xbe"       : "Java Class / Mach-O FAT",
    b"PK\x03\x04"             : "ZIP Archive",
    b"Rar!"                   : "RAR Archive",
    b"\x1f\x8b"               : "GZIP",
    b"\x25PDF"                : "PDF Document",
    b"\xd0\xcf\x11\xe0"       : "OLE2 (Office 97-2003)",
    b"<?xml"                  : "XML Document",
    b"<html"                  : "HTML Document",
    b"\x89PNG"                : "PNG Image",
    b"\xff\xd8\xff"           : "JPEG Image",
    b"GIF8"                   : "GIF Image",
    b"RIFF"                   : "RIFF (WAV/AVI)",
    b"\x00\x00\x00\x18ftyp"   : "MP4 Video",
    b"7z\xbc\xaf\x27\x1c"     : "7-Zip Archive",
}


def _read_magic_bytes(path: str, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _detect_magic_type(magic_bytes: bytes) -> str:
    for sig, desc in MAGIC_SIGS.items():
        if magic_bytes.startswith(sig):
            return desc
    return "Unknown / Data"


def _parse_pe_headers(path: str) -> Dict[str, Any]:
    """Parse PE (Windows executable) headers."""
    if not _PEFILE_AVAILABLE:
        return {"available": False}

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()

        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace") if entry.dll else "?"
                funcs    = [imp.name.decode(errors="replace") for imp in entry.imports if imp.name]
                imports.append({"dll": dll_name, "functions": funcs[:10]})

        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="replace")
            sections.append({
                "name"          : name,
                "virtual_size"  : s.Misc_VirtualSize,
                "raw_size"      : s.SizeOfRawData,
                "characteristics": hex(s.Characteristics),
            })

        suspicious_imports = _check_suspicious_imports(imports)

        return {
            "available"          : True,
            "machine"            : hex(pe.FILE_HEADER.Machine),
            "timestamp"          : pe.FILE_HEADER.TimeDateStamp,
            "subsystem"          : pe.OPTIONAL_HEADER.Subsystem,
            "num_sections"       : pe.FILE_HEADER.NumberOfSections,
            "sections"           : sections[:8],
            "imports"            : imports[:12],
            "suspicious_imports" : suspicious_imports,
        }
    except Exception as e:
        return {"available": True, "error": str(e)}


SUSPICIOUS_APIS = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "SetWindowsHookEx", "GetAsyncKeyState", "InternetOpenUrl",
    "URLDownloadToFile", "ShellExecute", "WinExec",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtSetInformationThread", "RegSetValueEx",
    "CryptEncrypt", "CryptDecrypt",
}


def _check_suspicious_imports(imports: List[Dict]) -> List[str]:
    found = []
    for entry in imports:
        for func in entry.get("functions", []):
            if func in SUSPICIOUS_APIS:
                found.append(f"{entry['dll']}!{func}")
    return found


def analyze_file_metadata(path: str, original_name: str) -> Dict[str, Any]:
    """
    Full static metadata analysis of a file.
    """
    p    = Path(path)
    ext  = Path(original_name).suffix.lstrip(".").lower()
    size = os.path.getsize(path)

    magic_bytes = _read_magic_bytes(path)
    magic_type  = _detect_magic_type(magic_bytes)

    # libmagic (more accurate)
    mime_type = "unknown"
    if _MAGIC_AVAILABLE:
        try:
            mime_type = libmagic.from_file(path, mime=True)
        except Exception:
            pass

    # Extension mismatch?
    mismatch = _check_extension_mismatch(ext, magic_bytes)

    # File risk
    if ext in HIGH_RISK_EXTS:
        risk = "HIGH"
    elif ext in MEDIUM_RISK_EXTS:
        risk = "MEDIUM"
    elif ext in LOW_RISK_EXTS:
        risk = "LOW"
    else:
        risk = "UNKNOWN"

    # PE parsing for .exe / .dll / magic MZ
    pe_info = {}
    if magic_bytes[:2] == b"MZ" or ext in ("exe", "dll", "sys", "scr"):
        pe_info = _parse_pe_headers(path)

    return {
        "original_name"    : original_name,
        "extension"        : ext or "none",
        "file_size_bytes"  : size,
        "magic_bytes_hex"  : magic_bytes[:8].hex(),
        "magic_type"       : magic_type,
        "mime_type"        : mime_type,
        "extension_mismatch": mismatch,
        "risk_level"       : risk,
        "pe_info"          : pe_info,
        "magic_available"  : _MAGIC_AVAILABLE,
        "pefile_available" : _PEFILE_AVAILABLE,
    }


def _check_extension_mismatch(ext: str, magic_bytes: bytes) -> bool:
    """Detect if extension doesn't match actual file type."""
    if magic_bytes[:2] == b"MZ" and ext not in ("exe", "dll", "sys", "scr", "com", "cpl", "msi", "ocx"):
        return True
    if magic_bytes[:4] == b"%PDF" and ext != "pdf":
        return True
    if magic_bytes[:2] == b"PK" and ext not in ("zip", "jar", "apk", "docx", "xlsx", "pptx", "odt"):
        return True
    return False
