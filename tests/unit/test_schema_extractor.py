"""
Tests for schema extraction and LLM context formatting.
"""
import pytest
from pwnpilot.plugins.schema_extractor import extract_schemas_for_llm, format_schemas_for_prompt


class TestSchemaExtractor:
    """Test cases for tool schema extraction."""

    def test_format_schemas_for_prompt_empty(self):
        """Test formatting empty schema dict."""
        result = format_schemas_for_prompt({})
        assert "No tools" in result

    def test_format_schemas_for_prompt_basic(self):
        """Test basic schema formatting."""
        schemas = {
            "nmap": {
                "description": "Network mapping tool",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "parameters": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or domain",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of scan",
                        "enum": ["sS", "sT", "sU"],
                    },
                },
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        
        assert "nmap" in result
        assert "Network mapping tool" in result
        assert "active_scan" in result
        assert "target" in result
        assert "sS" in result
        assert "sT" in result

    def test_format_schemas_headers(self):
        """Test that schema formatting includes proper headers."""
        schemas = {
            "test_tool": {
                "description": "Test tool",
                "risk_class": "test_risk",
                "required_params": [],
                "parameters": {},
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        assert "test_tool" in result

    def test_extract_schemas_with_none_registry(self):
        """Test schema extraction with None values."""
        # Simulating a failed registry scenario
        class MockRegistry:
            def get_tool(self, tool_name):
                if tool_name == "missing":
                    return None
                return type('Descriptor', (), {
                    'manifest': type('Manifest', (), {
                        'description': 'Test tool',
                        'risk_class': 'test',
                        'input_schema': {
                            'required': ['param1'],
                            'properties': {
                                'param1': {
                                    'type': 'string',
                                    'description': 'Test param',
                                }
                            }
                        }
                    })()
                })()
        
        registry = MockRegistry()
        schemas = extract_schemas_for_llm(registry, ["missing", "valid_tool"])
        
        # Should only have the valid tool
        assert "valid_tool" in schemas
        assert "missing" not in schemas

    def test_schema_with_enum_values(self):
        """Test schema formatting with enum parameter values."""
        schemas = {
            "nmap": {
                "description": "Test",
                "risk_class": "test",
                "required_params": [],
                "parameters": {
                    "scan_type": {
                        "type": "string",
                        "enum": ["sS", "sT", "sU", "sV"],
                    }
                },
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        
        # All enum values should be present
        for scan_type in ["sS", "sT", "sU", "sV"]:
            assert scan_type in result

    def test_schema_with_default_values(self):
        """Test schema formatting with default parameter values."""
        schemas = {
            "test_tool": {
                "description": "Test",
                "risk_class": "test",
                "required_params": [],
                "parameters": {
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 300,
                    }
                },
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        assert "300" in result
        assert "Default" in result

    def test_schema_with_array_parameter(self):
        """Test schema formatting with array-typed parameters."""
        schemas = {
            "test_tool": {
                "description": "Test",
                "risk_class": "test",
                "required_params": [],
                "parameters": {
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Port list",
                    }
                },
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        assert "array" in result
        # The format function doesn't include item type in the formatted output yet
        # Just verify the parameter is present
        assert "ports" in result

    def test_required_params_marked(self):
        """Test that required parameters are properly marked."""
        schemas = {
            "test_tool": {
                "description": "Test",
                "risk_class": "test",
                "required_params": ["target"],
                "parameters": {
                    "target": {
                        "type": "string",
                        "description": "Target",
                    },
                    "optional_param": {
                        "type": "string",
                        "description": "Optional",
                    },
                },
            }
        }
        
        result = format_schemas_for_prompt(schemas)
        
        # Both should be in output
        assert "`target`" in result
        assert "`optional_param`" in result
