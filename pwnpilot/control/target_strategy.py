"""Deterministic target strategy and tool-availability preflight helpers."""
from __future__ import annotations

from typing import Any


def classify_target_family(
    scope_cidrs: list[str],
    scope_domains: list[str],
    scope_urls: list[str],
) -> str:
    has_urls = bool(scope_urls)
    has_network = bool(scope_cidrs or scope_domains)

    if has_urls and has_network:
        return "mixed"
    if has_urls:
        return "web"
    if has_network:
        return "network"
    return "unknown"


def recommended_sequence_for_family(target_family: str) -> list[dict[str, Any]]:
    web = [
        {
            "step_id": "web_fingerprint",
            "name": "Fingerprint Web Stack",
            "goal": "Identify framework, headers, and baseline web technologies.",
            "preferred_tools": ["whatweb"],
            "fallback_tools": ["nikto"],
            "recovery_rules": [
                {
                    "hint_codes": ["output_format_invalid"],
                    "preferred_tools": ["nikto"],
                    "param_overrides": {},
                }
            ],
        },
        {
            "step_id": "web_discovery",
            "name": "Discover Routes/Endpoints",
            "goal": "Expand attack surface by crawling and directory/API discovery.",
            "preferred_tools": ["zap", "gobuster"],
            "fallback_tools": ["shell"],
            "recovery_rules": [
                {
                    "hint_codes": ["wildcard_detected"],
                    "preferred_tools": ["gobuster", "zap"],
                    "param_overrides": {
                        "gobuster": {
                            "force_wildcard": True,
                        }
                    },
                }
            ],
        },
        {
            "step_id": "web_vuln_scan",
            "name": "Run Web Vulnerability Scans",
            "goal": "Run template/signature scans against discovered endpoints.",
            "preferred_tools": ["nuclei", "nikto"],
            "fallback_tools": ["whatweb"],
            "recovery_rules": [
                {
                    "hint_codes": ["no_matches"],
                    "preferred_tools": ["nikto"],
                    "param_overrides": {},
                }
            ],
        },
        {
            "step_id": "web_injection_checks",
            "name": "Validate Injection and Auth Paths",
            "goal": "Perform targeted SQLi/form/API validation on discovered inputs.",
            "preferred_tools": ["sqlmap"],
            "fallback_tools": ["shell"],
            "recovery_rules": [
                {
                    "hint_codes": ["no_forms_detected"],
                    "preferred_tools": ["sqlmap", "shell"],
                    "param_overrides": {
                        "sqlmap": {
                            "forms": False,
                        }
                    },
                }
            ],
        },
    ]

    network = [
        {
            "step_id": "network_discovery",
            "name": "Discover Hosts and Ports",
            "goal": "Identify reachable hosts and open services in scope.",
            "preferred_tools": ["nmap", "dns", "whois"],
            "fallback_tools": ["shell"],
            "recovery_rules": [],
        },
        {
            "step_id": "network_service_enum",
            "name": "Enumerate Service Details",
            "goal": "Collect service versions and protocol details.",
            "preferred_tools": ["nmap"],
            "fallback_tools": ["whatweb", "shell"],
            "recovery_rules": [],
        },
        {
            "step_id": "network_vuln_scan",
            "name": "Scan for Vulnerabilities",
            "goal": "Check known vulnerabilities on discovered services.",
            "preferred_tools": ["nuclei", "nikto"],
            "fallback_tools": ["shell"],
            "recovery_rules": [
                {
                    "hint_codes": ["no_matches"],
                    "preferred_tools": ["nikto"],
                    "param_overrides": {},
                }
            ],
        },
    ]

    if target_family == "web":
        return web
    if target_family == "network":
        return network
    if target_family == "mixed":
        return web + network
    return [
        {
            "step_id": "generic_recon",
            "name": "Initial Reconnaissance",
            "goal": "Establish baseline connectivity and services.",
            "preferred_tools": ["whatweb", "nmap", "dns"],
            "fallback_tools": ["shell"],
            "recovery_rules": [],
        }
    ]


def build_engagement_strategy(
    scope_cidrs: list[str],
    scope_domains: list[str],
    scope_urls: list[str],
    available_tools: list[str],
) -> dict[str, Any]:
    target_family = classify_target_family(scope_cidrs, scope_domains, scope_urls)
    sequence = recommended_sequence_for_family(target_family)

    available = {t.strip() for t in available_tools if t and str(t).strip()}
    steps: list[dict[str, Any]] = []
    missing_recommended: set[str] = set()

    for step in sequence:
        preferred = [str(t) for t in step.get("preferred_tools", [])]
        fallback = [str(t) for t in step.get("fallback_tools", [])]

        preferred_available = [t for t in preferred if t in available]
        preferred_missing = [t for t in preferred if t not in available]
        fallback_available = [t for t in fallback if t in available]

        missing_recommended.update(preferred_missing)

        steps.append(
            {
                **step,
                "preferred_available": preferred_available,
                "preferred_missing": preferred_missing,
                "fallback_available": fallback_available,
                "step_ready": bool(preferred_available or fallback_available),
            }
        )

    return {
        "target_family": target_family,
        "sequence": steps,
        "missing_recommended_tools": sorted(missing_recommended),
        "install_guidance": {
            "suggested_command": "sudo bash scripts/install_security_tools.sh",
            "note": "If installation is denied, continue with available tools and fallback paths.",
        },
    }
