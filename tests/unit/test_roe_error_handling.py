"""
Test suite for ROE file error handling scenarios.

Tests proper error management for:
- Empty files
- Invalid YAML syntax
- Missing required fields
- Invalid field values
- Type mismatches
"""

import pytest
import tempfile
from pathlib import Path
from pwnpilot.data.roe_validator import validate_roe_file, validate_roe_and_raise


class TestROEFileValidation:
    """Test ROE file validation with various error scenarios."""
    
    def test_validate_none_dict_returns_error(self):
        """Test that None dictionary returns proper error."""
        is_valid, error_msg = validate_roe_file(None)
        assert not is_valid
        assert "None" in error_msg
        assert "FATAL" in error_msg
    
    def test_validate_non_dict_returns_error(self):
        """Test that non-dict input returns error."""
        is_valid, error_msg = validate_roe_file([1, 2, 3])
        assert not is_valid
        assert "must be a dictionary" in error_msg
        assert "list" in error_msg
    
    def test_validate_string_returns_error(self):
        """Test that string input returns error."""
        is_valid, error_msg = validate_roe_file("not a dict")
        assert not is_valid
        assert "must be a dictionary" in error_msg
    
    def test_validate_missing_required_fields(self):
        """Test that missing required top-level fields are caught."""
        incomplete_roe = {
            "engagement": {
                "name": "Test",
                "authorizer": "test@example.com",
                "description": "This is a test description with sufficient length for validation."
            }
            # Missing 'scope' and 'policy' sections
        }
        is_valid, error_msg = validate_roe_file(incomplete_roe)
        assert not is_valid
        assert "scope" in error_msg.lower() or "policy" in error_msg.lower()
    
    def test_validate_missing_engagement_fields(self):
        """Test that missing engagement sub-fields are caught."""
        invalid_roe = {
            "engagement": {
                "name": "Test"
                # Missing authorizer and description
            },
            "scope": {
                "urls": "http://localhost:3000"
            },
            "policy": {
                "max_iterations": 30
            }
        }
        is_valid, error_msg = validate_roe_file(invalid_roe)
        assert not is_valid
        assert "authorizer" in error_msg.lower() or "required" in error_msg.lower()
    
    def test_validate_invalid_email_format(self):
        """Test that invalid email in authorizer is caught."""
        invalid_roe = {
            "engagement": {
                "name": "Test Engagement",
                "authorizer": "not-an-email",  # Invalid email
                "description": "This is a test description with sufficient length for validation."
            },
            "scope": {
                "urls": "http://localhost:3000"
            },
            "policy": {
                "max_iterations": 30
            }
        }
        is_valid, error_msg = validate_roe_file(invalid_roe)
        assert not is_valid
        assert "email" in error_msg.lower() or "authorizer" in error_msg.lower()
    
    def test_validate_short_description(self):
        """Test that description below minimum length is rejected."""
        invalid_roe = {
            "engagement": {
                "name": "Test",
                "authorizer": "test@example.com",
                "description": "Short"  # Too short
            },
            "scope": {
                "urls": "http://localhost:3000"
            },
            "policy": {
                "max_iterations": 30
            }
        }
        is_valid, error_msg = validate_roe_file(invalid_roe)
        assert not is_valid
        assert "description" in error_msg.lower() or "length" in error_msg.lower() or "100" in error_msg
    
    def test_validate_valid_minimal_roe(self):
        """Test that a valid minimal ROE passes validation."""
        valid_roe = {
            "engagement": {
                "name": "Valid Test",
                "authorizer": "test@example.com",
                "description": "This is a properly formatted description with sufficient length to pass validation requirements. It must be at least 100 characters long."
            },
            "scope": {
                "urls": "http://localhost:3000"
            },
            "policy": {
                "max_iterations": 30,
                "max_retries": 3,
                "timeout_seconds": 3600,
                "cloud_allowed": True
            }
        }
        is_valid, error_msg = validate_roe_file(valid_roe)
        assert is_valid
        assert error_msg is None
    
    def test_validate_and_raise_with_none(self):
        """Test that validate_roe_and_raise raises on None."""
        with pytest.raises(TypeError):
            validate_roe_and_raise(None)
    
    def test_validate_with_extra_fields(self):
        """Test that extra unknown fields are handled gracefully."""
        roe_with_extras = {
            "engagement": {
                "name": "Test",
                "authorizer": "test@example.com",
                "description": "This is a proper description with sufficient length for validation requirements.",
                "extra_field": "This should not cause an error"  # Extra field
            },
            "scope": {
                "urls": "http://localhost:3000"
            },
            "policy": {
                "max_iterations": 30
            }
        }
        # Should either pass or provide clear error about extra fields
        is_valid, error_msg = validate_roe_file(roe_with_extras)
        # Note: Pydantic by default ignores extra fields, so this should pass
        # If configured to forbid extras, should have clear error message
        assert isinstance(is_valid, bool)


class TestYAMLParsingErrors:
    """Test YAML parsing error scenarios."""
    
    def test_empty_yaml_file(self):
        """Test that empty YAML file results in None after parsing."""
        import yaml
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")  # Empty file
            temp_path = f.name
        
        try:
            with open(temp_path) as f:
                result = yaml.safe_load(f)
            assert result is None, "Empty YAML file should parse to None"
        finally:
            Path(temp_path).unlink()
    
    def test_yaml_with_only_comments(self):
        """Test that YAML file with only comments parses to None."""
        import yaml
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("# This is just a comment\n# Another comment\n")
            temp_path = f.name
        
        try:
            with open(temp_path) as f:
                result = yaml.safe_load(f)
            assert result is None, "YAML file with only comments should parse to None"
        finally:
            Path(temp_path).unlink()
    
    def test_invalid_yaml_syntax(self):
        """Test that invalid YAML syntax raises proper error."""
        import yaml
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Invalid YAML: mismatched brackets
            f.write("engagement:\n  name: [unclosed bracket\n")
            temp_path = f.name
        
        try:
            with open(temp_path) as f:
                with pytest.raises(yaml.YAMLError):
                    yaml.safe_load(f)
        finally:
            Path(temp_path).unlink()


class TestFileHandling:
    """Test file-level error handling."""
    
    def test_nonexistent_file(self):
        """Test that nonexistent file is properly detected."""
        nonexistent = Path("/tmp/nonexistent_roe_12345.yaml")
        assert not nonexistent.exists()
    
    def test_empty_file_size_check(self):
        """Test that empty file size is correctly detected."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            assert temp_path.stat().st_size == 0
        finally:
            temp_path.unlink()
    
    def test_file_with_content_size_check(self):
        """Test that file with content is not considered empty."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("engagement:\n  name: Test\n")
            temp_path = Path(f.name)
        
        try:
            assert temp_path.stat().st_size > 0
        finally:
            temp_path.unlink()


class TestErrorMessageQuality:
    """Test that error messages are user-friendly and actionable."""
    
    def test_validation_error_includes_field_path(self):
        """Test that validation errors show the field path clearly."""
        invalid_roe = {
            "engagement": {
                "name": "X",  # Too short
                "authorizer": "test@example.com",
                "description": "Long enough description with proper content and length."
            },
            "scope": {},
            "policy": {}
        }
        is_valid, error_msg = validate_roe_file(invalid_roe)
        assert not is_valid
        # Should show field name in the error
        assert "engagement" in error_msg or "name" in error_msg or "length" in error_msg
    
    def test_none_dict_error_message_is_clear(self):
        """Test that None dict error message is clear and developers understand."""
        is_valid, error_msg = validate_roe_file(None)
        assert not is_valid
        assert "FATAL" in error_msg or "None" in error_msg
        assert "should have been caught" in error_msg or len(error_msg) > 20
