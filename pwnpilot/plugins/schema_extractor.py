"""
Tool Schema Extractor — generates parameter documentation for LLM planning context.

Extracts canonical parameter schemas from the tool registry to feed to the planner LLM.
This allows the LLM to understand exact parameter names, types, enums, and constraints
before generating proposals.

Usage::

    from pwnpilot.plugins.schema_extractor import extract_schemas_for_llm
    
    schemas = extract_schemas_for_llm(tool_registry, available_tools)
    context["tool_parameter_schemas"] = schemas
    # LLM now sees exact parameter contracts and can generate valid params
"""
from __future__ import annotations

from typing import Any


def extract_schemas_for_llm(
    tool_registry: Any,
    available_tool_names: list[str],
) -> dict[str, Any]:
    """
    Extract parameter schemas from available tools for LLM planning context.
    
    Args:
        tool_registry: ToolRegistry instance with tool descriptors
        available_tool_names: List of tool names to include in schema
    
    Returns:
        Dict mapping tool_name -> simplified schema for LLM consumption
        
    Example output::
    
        {
            "nmap": {
                "description": "Network mapping and service detection",
                "required_params": ["target", "scan_type"],
                "parameters": {
                    "target": {
                        "type": "string",
                        "description": "IP address, CIDR, or hostname"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["sS", "sT", "sU", "-sV"],
                        "description": "Nmap scan type flag"
                    }
                }
            }
        }
    """
    schemas: dict[str, Any] = {}
    
    for tool_name in available_tool_names:
        try:
            descriptor = tool_registry.get_tool(tool_name)
            if not descriptor or not descriptor.manifest:
                continue
            
            manifest = descriptor.manifest
            input_schema = manifest.input_schema if hasattr(manifest, 'input_schema') else {}
            
            # Build LLM-friendly schema summary
            tool_schema = {
                "description": manifest.description if hasattr(manifest, 'description') else "",
                "risk_class": manifest.risk_class if hasattr(manifest, 'risk_class') else "unknown",
            }
            
            # Extract required and optional params
            if isinstance(input_schema, dict):
                required = input_schema.get("required", [])
                properties = input_schema.get("properties", {})
                
                tool_schema["required_params"] = required
                
                # Simplify parameter docs for LLM
                tool_schema["parameters"] = {}
                for param_name, param_spec in properties.items():
                    if not isinstance(param_spec, dict):
                        continue
                    
                    param_doc = {
                        "type": param_spec.get("type", "unknown"),
                        "description": param_spec.get("description", ""),
                    }
                    
                    # Include enum values if present
                    if "enum" in param_spec:
                        param_doc["enum"] = param_spec["enum"]
                    
                    # Include default if present
                    if "default" in param_spec:
                        param_doc["default"] = param_spec["default"]
                    
                    # For arrays, include item type
                    if param_spec.get("type") == "array" and "items" in param_spec:
                        param_doc["items_type"] = param_spec["items"].get("type", "unknown")
                    
                    tool_schema["parameters"][param_name] = param_doc
            
            schemas[tool_name] = tool_schema
        
        except Exception as exc:
            # Skip tools with schema extraction errors
            import structlog
            log = structlog.get_logger(__name__)
            log.warning(
                "schema_extractor.error",
                tool=tool_name,
                exc=str(exc),
            )
            continue
    
    return schemas


def format_schemas_for_prompt(schemas: dict[str, Any]) -> str:
    """
    Format extracted schemas into a readable prompt segment for the LLM.
    
    Returns a markdown-like string describing all available tools and their parameters.
    """
    import json
    
    if not schemas:
        return "No tools available with schemas."
    
    lines = ["## Tool Parameter Reference\n"]
    
    for tool_name in sorted(schemas.keys()):
        tool_schema = schemas[tool_name]
        lines.append(f"### {tool_name}")
        
        if tool_schema.get("description"):
            lines.append(f"**Description:** {tool_schema['description']}")
        
        if tool_schema.get("risk_class"):
            lines.append(f"**Risk Class:** {tool_schema['risk_class']}")
        
        if tool_schema.get("required_params"):
            lines.append(f"**Required Parameters:** {', '.join(tool_schema['required_params'])}")
        
        if tool_schema.get("parameters"):
            lines.append("**Parameters:**")
            
            for param_name, param_doc in tool_schema["parameters"].items():
                param_type = param_doc.get("type", "unknown")
                desc = param_doc.get("description", "")
                
                lines.append(f"  - `{param_name}` ({param_type}): {desc}")
                
                if "enum" in param_doc:
                    enum_values = param_doc["enum"]
                    lines.append(f"    Allowed values: {', '.join(map(str, enum_values))}")
                
                if "default" in param_doc:
                    lines.append(f"    Default: {param_doc['default']}")
        
        lines.append("")
    
    return "\n".join(lines)
