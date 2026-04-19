from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ToolManifestSpec:
    name: str
    version: str
    risk_class: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    args_template: list[Any]
    parse_strategy: str
    capabilities: dict[str, Any]
    binary_name: str
    checksum_sha256: str = ""
    signature_b64: str = ""


def _as_dict(raw: Any) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _as_list(raw: Any) -> list[Any]:
    return raw if isinstance(raw, list) else []


def load_manifest_file(path: Path) -> ToolManifestSpec:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid manifest format in {path}")

    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError(f"Manifest missing name: {path}")

    parse_cfg = _as_dict(data.get("parse"))
    strategy = str(parse_cfg.get("strategy", "")).strip()
    if not strategy:
        raise ValueError(f"Manifest missing parse.strategy: {path}")

    return ToolManifestSpec(
        name=name,
        version=str(data.get("version", "1.0")).strip() or "1.0",
        risk_class=str(data.get("risk_class", "recon_passive")).strip() or "recon_passive",
        description=str(data.get("description", "")).strip(),
        input_schema=_as_dict(data.get("input_schema")),
        output_schema=_as_dict(data.get("output_schema")),
        args_template=_as_list(data.get("args")),
        parse_strategy=strategy,
        capabilities=_as_dict(data.get("capabilities")),
        binary_name=str(data.get("binary", "")).strip(),
        checksum_sha256=str(data.get("checksum_sha256", "")).strip(),
        signature_b64=str(data.get("signature_b64", "")).strip(),
    )


def load_manifests_dir(manifest_dir: Path) -> list[ToolManifestSpec]:
    if not manifest_dir.exists() or not manifest_dir.is_dir():
        return []

    out: list[ToolManifestSpec] = []
    for mf in sorted(manifest_dir.glob("*.yaml")):
        out.append(load_manifest_file(mf))
    return out
