"""
nmap adapter — port scanning and service/version detection.

Risk class: active_scan
Input: target (IP, CIDR, hostname), ports, scan_type
Output: list of hosts with open ports and service banners
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

_ALLOWED_SCAN_TYPES = frozenset({"sT", "sS", "sV", "sU", "sn", "A", "O"})
_PORT_PATTERN = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$|^-$")
# Allow only safe target characters: alphanumeric, dots, hyphens, forward-slash (CIDR), brackets (IPv6)
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:/\[\]_]+$")


class NmapAdapter(BaseAdapter):
    """
    Adapter for nmap port scanner.  Produces XML output (-oX -) for reliable parsing.
    """

    _MANIFEST = PluginManifest(
        name="nmap",
        version="7.94",
        risk_class="active_scan",
        description="Network port scanner and service/OS detection",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string", "default": "1-1024"},
                "scan_type": {"type": "string", "default": "sV"},
                "timing": {"type": "integer", "minimum": 0, "maximum": 5, "default": 3},
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "hosts": {"type": "array"},
                "services": {"type": "array"},
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("nmap: 'target' parameter is required.")

        # Reject targets with shell-special or path-traversal characters
        if not _SAFE_TARGET_RE.match(target):
            raise ValueError(
                f"nmap: target contains unsafe characters: {target!r}. "
                "Only alphanumeric, dots, hyphens, slashes, and brackets are allowed."
            )

        ports = str(params.get("ports", "1-1024")).strip()
        if not _PORT_PATTERN.match(ports):
            raise ValueError(f"nmap: invalid port specification: {ports!r}")

        scan_type = str(params.get("scan_type", "sV")).strip().lstrip("-")
        if scan_type not in _ALLOWED_SCAN_TYPES:
            raise ValueError(
                f"nmap: scan_type '{scan_type}' is not allow-listed. "
                f"Allowed: {_ALLOWED_SCAN_TYPES}"
            )

        timing = int(params.get("timing", 3))
        if not 0 <= timing <= 5:
            raise ValueError(f"nmap: timing template must be 0-5, got {timing}")

        return ToolParams(
            target=target,
            extra={"ports": ports, "scan_type": scan_type, "timing": timing},
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """
        Build the nmap subprocess command list.
        MUST return list[str] — no shell interpolation (ADR-002).
        """
        scan_type = f"-{params.extra['scan_type']}"
        timing = f"-T{params.extra['timing']}"
        ports = f"-p{params.extra['ports']}"
        return [
            "nmap",
            scan_type,
            timing,
            ports,
            "-oX", "-",          # XML output to stdout
            "--open",            # show only open ports
            params.target,
        ]

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if not stdout or exit_code not in (0, 1):
            return ParsedOutput(
                parser_error=f"nmap exited with code {exit_code}",
                confidence=0.0,
            )

        try:
            root = ET.fromstring(stdout.decode(errors="replace"))
        except ET.ParseError as exc:
            return ParsedOutput(parser_error=f"XML parse error: {exc}", confidence=0.0)

        hosts = []
        services = []

        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue

            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue

            ip = addr_el.attrib.get("addr", "")
            hostname = ""
            hostnames_el = host_el.find("hostnames/hostname")
            if hostnames_el is not None:
                hostname = hostnames_el.attrib.get("name", "")

            os_guess = ""
            os_match = host_el.find("os/osmatch")
            if os_match is not None:
                os_guess = os_match.attrib.get("name", "")

            hosts.append({"ip": ip, "hostname": hostname, "os_guess": os_guess})

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue

                portid = int(port_el.attrib.get("portid", 0))
                protocol = port_el.attrib.get("protocol", "tcp")

                service_el = port_el.find("service")
                svc_name = product = version = banner = ""
                if service_el is not None:
                    svc_name = service_el.attrib.get("name", "")
                    product = service_el.attrib.get("product", "")
                    version = service_el.attrib.get("version", "")

                services.append(
                    {
                        "ip": ip,
                        "port": portid,
                        "protocol": protocol,
                        "service_name": svc_name,
                        "product": product,
                        "version": version,
                    }
                )

        return ParsedOutput(
            hosts=hosts,
            services=services,
            raw_summary=f"Discovered {len(hosts)} host(s), {len(services)} service(s)",
            new_findings_count=len(services),
            confidence=0.9 if hosts else 0.3,
        )
