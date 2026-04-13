"""OS-aware tool binary resolution helpers."""
from __future__ import annotations

import platform
import shutil

_TOOL_BINARY_ALIASES: dict[str, dict[str, list[str]]] = {
    "dns": {
        "linux": ["dig", "drill", "nslookup"],
        "darwin": ["dig", "nslookup"],
        "windows": ["nslookup", "dig.exe"],
        "default": ["dig", "nslookup"],
    },
    "zap": {
        "linux": [
            "zap-baseline.py",
            "/usr/share/zaproxy/zap-baseline.py",
            "/snap/zaproxy/current/zap-baseline.py",
        ],
        "darwin": ["zap-baseline.py", "/Applications/ZAP.app/Contents/Java/zap-baseline.py"],
        "windows": ["zap-baseline.py", "zap-baseline.bat"],
        "default": ["zap-baseline.py"],
    },
    "gobuster": {
        "linux": ["gobuster"],
        "darwin": ["gobuster"],
        "windows": ["gobuster.exe", "gobuster"],
        "default": ["gobuster"],
    },
}


def _normalized_os() -> str:
    name = platform.system().lower()
    if "windows" in name:
        return "windows"
    if "darwin" in name or "mac" in name:
        return "darwin"
    if "linux" in name:
        return "linux"
    return "default"


def candidate_binaries(tool_name: str, requested_binary: str) -> list[str]:
    """Return ordered binary candidates for the given tool on this OS."""
    os_name = _normalized_os()
    aliases = _TOOL_BINARY_ALIASES.get(tool_name, {})
    candidates = []
    if requested_binary:
        candidates.append(requested_binary)
    candidates.extend(aliases.get(os_name, []))
    candidates.extend(aliases.get("default", []))

    seen: set[str] = set()
    ordered: list[str] = []
    for item in candidates:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


def resolve_binary_for_tool(tool_name: str, requested_binary: str) -> str | None:
    """Return an executable path/name for the current OS, or None if unavailable."""
    for candidate in candidate_binaries(tool_name, requested_binary):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None
