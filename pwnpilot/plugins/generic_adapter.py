from __future__ import annotations

import ast
import re
from typing import Any

from pwnpilot.plugins.manifest_loader import ToolManifestSpec
from pwnpilot.plugins.parsers.strategies import get_parse_strategy
from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams


class _ExprValidator(ast.NodeVisitor):
    _ALLOWED_NODES = (
        ast.Expression,
        ast.BoolOp,
        ast.UnaryOp,
        ast.Name,
        ast.Load,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Constant,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
    )

    def generic_visit(self, node: ast.AST) -> Any:
        if not isinstance(node, self._ALLOWED_NODES):
            raise ValueError(f"Unsupported expression element: {type(node).__name__}")
        return super().generic_visit(node)


def _eval_when(expr: str, context: dict[str, Any]) -> bool:
    tree = ast.parse(expr, mode="eval")
    _ExprValidator().visit(tree)
    return bool(eval(compile(tree, "<manifest-when>", "eval"), {"__builtins__": {}}, context))


_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


class GenericCLIAdapter(BaseAdapter):
    def __init__(self, spec: ToolManifestSpec) -> None:
        self._spec = spec
        self._manifest = PluginManifest(
            name=spec.name,
            version=spec.version,
            risk_class=spec.risk_class,
            description=spec.description,
            input_schema=spec.input_schema,
            output_schema=spec.output_schema,
            checksum_sha256=spec.checksum_sha256,
            signature_b64=spec.signature_b64,
            schema_version="v1",
        )
        self.binary_name = spec.binary_name

    @property
    def manifest(self) -> PluginManifest:
        return self._manifest

    def _required_params(self) -> list[str]:
        return [str(v) for v in self._spec.input_schema.get("required", [])]

    def _properties(self) -> dict[str, Any]:
        props = self._spec.input_schema.get("properties", {})
        return props if isinstance(props, dict) else {}

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        if not isinstance(params, dict):
            raise ValueError(f"{self._spec.name}: params must be an object")

        props = self._properties()
        required = self._required_params()

        for key in required:
            if key not in params or params.get(key) in (None, ""):
                raise ValueError(f"{self._spec.name}: '{key}' parameter is required.")

        normalized: dict[str, Any] = {}
        for key, schema in props.items():
            schema = schema if isinstance(schema, dict) else {}
            if key in params:
                value = params[key]
            else:
                value = schema.get("default")

            if value is None:
                continue

            typ = str(schema.get("type", "")).strip()
            if typ == "integer":
                if isinstance(value, bool):
                    raise ValueError(f"{self._spec.name}: '{key}' must be an integer")
                value = int(value)
                mn = schema.get("minimum")
                mx = schema.get("maximum")
                if mn is not None and value < int(mn):
                    raise ValueError(f"{self._spec.name}: '{key}' must be >= {mn}")
                if mx is not None and value > int(mx):
                    raise ValueError(f"{self._spec.name}: '{key}' must be <= {mx}")
            elif typ == "boolean":
                value = bool(value)
            elif typ == "array":
                if not isinstance(value, list):
                    raise ValueError(f"{self._spec.name}: '{key}' must be an array")
            elif typ == "string":
                value = str(value)
                enum = schema.get("enum")
                if isinstance(enum, list) and enum and value not in enum:
                    raise ValueError(f"{self._spec.name}: '{key}' must be one of {enum}")
            normalized[key] = value

        target = str(params.get("target", normalized.get("target", params.get("query", "")))).strip()
        if not target:
            # Some tools can use query as semantic target.
            target = str(params.get("query", "")).strip()
        return ToolParams(target=target, extra=normalized)

    def _render_token(self, token: str, values: dict[str, Any]) -> str:
        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            return str(values.get(key, ""))

        return _PLACEHOLDER_RE.sub(repl, token)

    def build_command(self, params: ToolParams) -> list[str]:
        values = {"target": params.target, **params.extra}
        cmd: list[str] = []
        for item in self._spec.args_template:
            if isinstance(item, str):
                rendered = self._render_token(item, values).strip()
                if rendered:
                    cmd.append(rendered)
                continue

            if isinstance(item, dict):
                when_expr = str(item.get("when", "")).strip()
                if when_expr and not _eval_when(when_expr, values):
                    continue
                parts = item.get("parts", [])
                if isinstance(parts, list):
                    for part in parts:
                        rendered = self._render_token(str(part), values).strip()
                        if rendered:
                            cmd.append(rendered)
                continue

        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        parser = get_parse_strategy(self._spec.parse_strategy)
        return parser(stdout, stderr, exit_code)
