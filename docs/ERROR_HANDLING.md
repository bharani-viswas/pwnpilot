# Error Handling Patterns for PwnPilot

## Overview
This document defines the error handling patterns used throughout PwnPilot to ensure consistent, user-friendly error messages and proper input validation.

## Core Principles

1. **Fail Fast**: Validate input at the earliest possible point
2. **Clear Errors**: Provide actionable error messages with context
3. **Defensive Checks**: Add checks at multiple levels, don't rely on single validation point
4. **User Hints**: Include hints for common issues (e.g., "File is empty. Did you mean to create a ROE file?")

## Pattern: File Input Validation

### Level 1: CLI Entry Point (Earliest Check)
```python
# Check file exists
if not file_path.exists():
    raise CLIError(f"File not found: {file_path}")

# Check file is not empty (BEFORE parsing)
if file_path.stat().st_size == 0:
    raise CLIError(f"File is empty: {file_path}")
    
# Check file is readable
try:
    file_path.stat()
except PermissionError:
    raise CLIError(f"Permission denied reading file: {file_path}")
```

### Level 2: Content Parsing
```python
try:
    content = file_path.read_text()
    parsed = yaml.safe_load(content)
except yaml.YAMLError as e:
    raise CLIError(f"Invalid YAML in {file_path}: {e}")
except Exception as e:
    raise CLIError(f"Error reading {file_path}: {e}")
```

### Level 3: Explicit None Check
```python
if parsed is None:
    raise CLIError(f"File contains no valid YAML content: {file_path}")
```

### Level 4: Schema Validation
```python
try:
    schema_obj = SchemaClass(**parsed)
except ValidationError as e:
    raise CLIError(f"Validation failed in {file_path}:\n{format_errors(e)}")
```

## Pattern: Data Validation

### Multi-Level Validation
```python
def validate_data(data):
    """Validate with clear error messages at each step."""
    
    # Level 1: Type check
    if not isinstance(data, dict):
        return False, f"Expected dictionary, got {type(data).__name__}"
    
    # Level 2: Required fields
    required = {'field1', 'field2', 'field3'}
    missing = required - set(data.keys())
    if missing:
        return False, f"Missing required fields: {missing}"
    
    # Level 3: Field-level validation
    errors = []
    for field_name, field_value in data.items():
        if not validate_field(field_name, field_value):
            errors.append(f"{field_name}: {get_field_error(field_name)}")
    
    if errors:
        return False, "\n".join(errors)
    
    return True, None
```

### Return Value Pattern
**Consistent returns** for validators:
- Success: `(True, None)` - tuple with True and None
- Failure: `(False, error_message)` - tuple with False and descriptive message

```python
# Good
is_valid, error_msg = validate(data)
if not is_valid:
    handle_error(error_msg)

# Avoid mixing patterns
# Bad: Sometimes returns None, sometimes returns False
# Bad: Returns data on success, None on failure
```

## Pattern: User-Friendly Error Messages

### Structure of Error Messages
```
[error-type]: brief-description
  field → sub-field: specific issue (e.g., "must be at least 8 characters")
  another-field: another issue

Hint: suggestion for fixing the issue
```

### Example
```
ROE Validation Failed:
  engagement → name: String should have at least 8 characters
  engagement → description: String should have at least 100 characters
  
Hint: Make sure your engagement name is at least 8 characters and description is at least 100.
```

### Color Coding (Rich/CLI)
- `[red]` for errors
- `[yellow]` for hints/warnings
- `[green]` for success messages
- `[cyan]` for section headers

## Pattern: Exception Hierarchy

```python
class PwnPilotError(Exception):
    """Base class for all pwnpilot errors."""
    pass

class ConfigurationError(PwnPilotError):
    """Raised when configuration is invalid."""
    pass

class ValidationError(PwnPilotError):
    """Raised when data validation fails."""
    pass

class FileHandlingError(PwnPilotError):
    """Raised when file operations fail."""
    pass

# Usage
try:
    validate_roe(file_content)
except ValidationError as e:
    logger.error("validation_failed", error=str(e))
    sys.exit(1)
```

## Pattern: Logging + User Output

### Layered Output
```python
import structlog

log = structlog.get_logger(__name__)

def process_roe_file(file_path):
    try:
        # Log structured data for debugging
        log.info("roe.processing_started", file=str(file_path))
        
        content = load_file(file_path)
        log.debug("roe.file_loaded", size=len(content))
        
        parsed = parse_yaml(content)
        log.debug("roe.parsed", keys=list(parsed.keys()))
        
        is_valid = validate_roe(parsed)
        if not is_valid:
            log.error("roe.validation_failed", reason="schema mismatch")
            # User-friendly message to console
            console.print("[red]Error: ROE validation failed[/red]")
            return False
        
        log.info("roe.processing_complete")
        console.print("[green]✓ ROE loaded successfully[/green]")
        return True
        
    except FileNotFoundError as e:
        log.error("roe.file_not_found", file=str(file_path))
        console.print(f"[red]Error: ROE file not found: {file_path}[/red]")
        return False
    except Exception as e:
        log.error("roe.unexpected_error", error=str(e), exc_info=True)
        console.print(f"[red]Unexpected error: {e}[/red]")
        return False
```

## Testing Error Handling

### Test Patterns
1. **Happy Path**: Verify success cases work
2. **Sad Paths**: Test each error condition independently
3. **Edge Cases**: Empty, None, wrong types, boundary values
4. **Error Messages**: Verify messages are helpful and include context

### Example Test Structure
```python
class TestValidation:
    def test_valid_input_succeeds(self):
        """Happy path: valid input passes validation."""
        result = validate(valid_data)
        assert result is True
    
    def test_missing_required_field_fails(self):
        """Sad path: missing field raises clear error."""
        is_valid, error = validate(data_missing_field)
        assert not is_valid
        assert "required" in error.lower()
        assert "field_name" in error
    
    def test_error_message_includes_context(self):
        """Verify error messages are helpful."""
        _, error = validate(invalid_data)
        # Should mention what's wrong and what's expected
        assert "expected" in error.lower() or "must be" in error.lower()
```

## Checklist for New Features

When adding new file input or parsing functionality:

- [ ] Add file existence check before parsing
- [ ] Add file size/emptiness check before parsing  
- [ ] Add explicit null/None check after parsing
- [ ] Handle YAML/JSON parsing errors gracefully
- [ ] Add schema validation with Pydantic
- [ ] Include structured logging for debugging
- [ ] Include user-friendly console messages with hints
- [ ] Write tests for all error cases
- [ ] Test that error messages include file path/context
- [ ] Verify error messages suggest how to fix issues

## Common Mistakes to Avoid

1. **No early checks**: Don't skip the file existence/size checks and rely only on parsing errors
2. **Silent failures**: Don't parse errors that result in None/empty and proceed silently
3. **Generic errors**: Don't just say "failed" - explain what failed and why
4. **Missing context**: Don't forget to include file names, fields, values in error messages
5. **No user hints**: Don't leave users guessing about how to fix issues
6. **Inconsistent patterns**: Don't mix validation approaches - use consistent patterns

## References

- Pydantic validation: https://docs.pydantic.dev/latest/
- Rich console: https://rich.readthedocs.io/
- Structlog logging: https://www.structlog.org/
