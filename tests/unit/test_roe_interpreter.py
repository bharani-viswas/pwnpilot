"""
Comprehensive test suite for ROE Interpreter.

Tests cover:
- Valid ROE interpretation
- Anti-injection detection
- Anti-hallucination detection
- Conflict detection
- Confidence scoring
- LLM error handling
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pwnpilot.agent.roe_interpreter import (
    ROEInterpreter,
    ExtractedPolicy,
    InterpretationResult,
    interpret_roe,
)


# ============================================================================
# FIXTURES: Test Data
# ============================================================================

@pytest.fixture
def valid_roe_dict():
    """Valid, simple ROE for testing."""
    return {
        "engagement": {
            "name": "test-engagement-001",
            "authorizer": "test@company.com",
            "description": "Test engagement with comprehensive scope and policy parameters.",
            "valid_hours": 24,
        },
        "scope": {
            "cidrs": "10.0.0.0/8",
            "domains": "api.company.com",
            "urls": "https://api.company.com/v1",
            "excluded_ips": "",
            "restricted_actions": "MODIFY_DATA,DELETE_DATA",
        },
        "policy": {
            "cloud_allowed": False,
            "max_iterations": 50,
            "max_retries": 3,
        },
    }


@pytest.fixture
def complex_roe_dict():
    """Complex ROE with multiple scopes and restrictions."""
    return {
        "engagement": {
            "name": "complex-pentest-2024-01",
            "authorizer": "ciso@company.com",
            "description": "Complex engagement testing multiple scope types and restricted actions comprehensively.",
            "valid_hours": 40,
        },
        "scope": {
            "cidrs": "10.0.0.0/8,172.16.0.0/12",
            "domains": "api.company.com,admin.company.com",
            "urls": "https://api.company.com/v1,https://admin.company.com",
            "excluded_ips": "10.0.1.1,10.0.1.5",
            "restricted_actions": "MODIFY_DATA,DELETE_DATA,ENCRYPT_DATA",
        },
        "policy": {
            "cloud_allowed": True,
            "max_iterations": 100,
            "max_retries": 5,
        },
    }


@pytest.fixture
def mock_litellm_valid_response():
    """Mock LLM response for valid ROE."""
    return {
        "scope_cidrs": ["10.0.0.0/8"],
        "scope_domains": ["api.company.com"],
        "scope_urls": ["https://api.company.com/v1"],
        "excluded_ips": [],
        "restricted_actions": ["MODIFY_DATA", "DELETE_DATA"],
        "max_iterations": 50,
        "max_retries": 3,
        "cloud_allowed": False,
    }


@pytest.fixture
def mock_litellm_injection_response():
    """Mock LLM response attempting injection (unknown actions)."""
    return {
        "scope_cidrs": ["10.0.0.0/8"],
        "scope_domains": ["api.company.com"],
        "scope_urls": ["https://api.company.com/v1"],
        "excluded_ips": [],
        "restricted_actions": ["MODIFY_DATA", "UNKNOWN_ACTION"],  # Injection attempt
        "max_iterations": 50,
        "max_retries": 3,
        "cloud_allowed": False,
    }


@pytest.fixture
def mock_litellm_hallucination_response():
    """Mock LLM response with hallucinated values.""" 
    return {
        "scope_cidrs": ["10.0.0.0/8"],
        "scope_domains": ["api.company.com", "hallucinated.com"],  # Hallucinated domain
        "scope_urls": ["https://api.company.com/v1"],
        "excluded_ips": [],
        "restricted_actions": ["MODIFY_DATA", "DELETE_DATA"],
        "max_iterations": 200,  # Different from ROE (50)
        "max_retries": 3,
        "cloud_allowed": False,
    }


# ============================================================================
# TESTS: Basic Functionality
# ============================================================================

class TestROEInterpreterBasics:
    """Test basic interpreter functionality."""

    def test_interpreter_initialization(self):
        """ROEInterpreter should initialize successfully."""
        interpreter = ROEInterpreter()
        assert interpreter.warnings == []
        assert interpreter.concerns == []
        assert interpreter.hallucination_risks == []

    def test_extracted_policy_to_dict(self):
        """ExtractedPolicy should convert to dictionary."""
        policy = ExtractedPolicy(
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=["api.company.com"],
            scope_urls=["https://api.company.com/v1"],
            excluded_ips=["10.0.1.1"],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=50,
            max_retries=3,
            cloud_allowed=False,
        )
        
        result_dict = policy.to_dict()
        assert result_dict["scope_cidrs"] == ["10.0.0.0/8"]
        assert result_dict["max_iterations"] == 50
        assert result_dict["cloud_allowed"] is False

    def test_interpretation_result_to_dict(self):
        """InterpretationResult should convert to dictionary."""
        policy = ExtractedPolicy(
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=["api.company.com"],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=[],
            max_iterations=50,
            max_retries=3,
            cloud_allowed=False,
        )
        
        result = InterpretationResult(
            is_valid=True,
            extracted_policy=policy,
            confidence_score=0.95,
            warnings=["test warning"],
            concerns=[],
            hallucination_risks=[],
            injection_detected=False,
        )
        
        result_dict = result.to_dict()
        assert result_dict["is_valid"] is True
        assert result_dict["confidence_score"] == 0.95
        assert result_dict["extracted_policy"]["max_iterations"] == 50


# ============================================================================
# TESTS: LLM Integration (Mocked)
# ============================================================================

class TestLLMIntegration:
    """Test LLM integration and response parsing."""

    @patch('litellm.completion')
    def test_successful_llm_extraction(self, mock_completion, valid_roe_dict, mock_litellm_valid_response):
        """LLM extraction should return valid ExtractedPolicy."""
        # Mock LLM response
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_valid_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.is_valid is True
        assert result.extracted_policy is not None
        assert result.extracted_policy.max_iterations == 50
        assert result.injection_detected is False

    @patch('litellm.completion')
    def test_llm_error_handling(self, mock_completion, valid_roe_dict):
        """LLM errors should be handled gracefully."""
        # Mock LLM error
        mock_completion.side_effect = Exception("API Error")
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.is_valid is False
        assert result.confidence_score == 0.0
        assert result.error_message is not None
        assert "failed" in result.error_message.lower()

    @patch('litellm.completion')
    def test_llm_invalid_json_handling(self, mock_completion, valid_roe_dict):
        """Invalid JSON in LLM response should be handled."""
        # Mock invalid JSON response
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content="This is not valid JSON"
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.is_valid is False
        assert result.error_message is not None


# ============================================================================
# TESTS: Injection Detection
# ============================================================================

class TestInjectionDetection:
    """Test injection attack detection."""

    @patch('litellm.completion')
    def test_unknown_action_injection_detected(self, mock_completion, valid_roe_dict, mock_litellm_injection_response):
        """Unknown action values should be detected as injection."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_injection_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.injection_detected is True
        assert any("Unknown actions" in concern for concern in result.concerns)

    @patch('litellm.completion')
    def test_invalid_action_detection(self, mock_completion, valid_roe_dict):
        """Invalid action values not in whitelist should be detected."""
        injection_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": ["api.company.com"],
            "scope_urls": ["https://api.company.com/v1"],
            "excluded_ips": [],
            "restricted_actions": ["INVALID_ACTION"],
            "max_iterations": 50,
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(injection_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.injection_detected is True
        assert any("Invalid action" in concern for concern in result.concerns)

    @patch('litellm.completion')
    def test_no_injection_on_valid_extraction(self, mock_completion, valid_roe_dict, mock_litellm_valid_response):
        """Valid extraction should not be flagged as injection."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_valid_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.injection_detected is False


# ============================================================================
# TESTS: Hallucination Detection
# ============================================================================

class TestHallucinationDetection:
    """Test hallucination detection and confidence scoring."""

    @patch('litellm.completion')
    def test_hallucination_on_different_max_iterations(self, mock_completion, valid_roe_dict, mock_litellm_hallucination_response):
        """Different max_iterations value should be detected as hallucination."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_hallucination_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert len(result.hallucination_risks) > 0
        assert any("max_iterations" in risk for risk in result.hallucination_risks)
        assert result.confidence_score < 1.0

    @patch('litellm.completion')
    def test_low_confidence_on_multiple_hallucinations(self, mock_completion, valid_roe_dict):
        """Multiple hallucinations should reduce confidence below threshold."""
        hallucination_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": ["api.company.com"],
            "scope_urls": ["https://api.company.com/v1"],
            "excluded_ips": [],
            "restricted_actions": [],
            "max_iterations": 200,  # Wrong
            "max_retries": 3,
            "cloud_allowed": True,  # Wrong
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(hallucination_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.confidence_score < ROEInterpreter.HALLUCINATION_THRESHOLD
        assert any("LOW CONFIDENCE" in concern for concern in result.concerns)

    @patch('litellm.completion')
    def test_unrealistic_values_detected(self, mock_completion, valid_roe_dict):
        """Unrealistic policy values should be flagged as hallucinations."""
        unrealistic_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": ["api.company.com"],
            "scope_urls": ["https://api.company.com/v1"],
            "excluded_ips": [],
            "restricted_actions": [],
            "max_iterations": 2000,  # Out of range [1-1000]
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(unrealistic_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert len(result.hallucination_risks) > 0


# ============================================================================
# TESTS: Conflict Detection
# ============================================================================

class TestConflictDetection:
    """Test conflict detection in extracted policies."""

    @patch('litellm.completion')
    def test_excluded_ip_outside_scope_detected(self, mock_completion, valid_roe_dict):
        """Excluded IP outside scope CIDRs should be detected."""
        conflict_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": [],
            "scope_urls": [],
            "excluded_ips": ["192.168.1.1"],  # Outside 10.0.0.0/8
            "restricted_actions": [],
            "max_iterations": 50,
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(conflict_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert len(result.concerns) > 0
        assert any("Conflict" in concern and "not in scope" in concern for concern in result.concerns)

    @patch('litellm.completion')
    def test_low_max_iterations_warning(self, mock_completion, valid_roe_dict):
        """Very low max_iterations should be flagged as conflict."""
        conflict_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": [],
            "scope_urls": [],
            "excluded_ips": [],
            "restricted_actions": [],
            "max_iterations": 5,  # Unusually low
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(conflict_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert any("very low" in concern.lower() for concern in result.concerns)


# ============================================================================
# TESTS: Confidence Scoring
# ============================================================================

class TestConfidenceScoring:
    """Test confidence score calculations."""

    @patch('litellm.completion')
    def test_high_confidence_on_perfect_extraction(self, mock_completion, valid_roe_dict, mock_litellm_valid_response):
        """Perfect extraction should have high confidence."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_valid_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.confidence_score >= 0.95
        assert result.injection_detected is False

    @patch('litellm.completion')
    def test_confidence_penalty_for_injection(self, mock_completion, valid_roe_dict, mock_litellm_injection_response):
        """Injection detection should reduce confidence significantly."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_injection_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        # Should have 30% penalty for injection + 5% for 1 conflict = 65% confidence
        assert result.confidence_score < 0.70
        assert result.injection_detected is True

    @patch('litellm.completion')
    def test_confidence_penalty_for_conflicts(self, mock_completion, valid_roe_dict):
        """Each conflict should reduce confidence by 5%."""
        conflict_response = {
            "scope_cidrs": ["10.0.0.0/8"],
            "scope_domains": [],
            "scope_urls": [],
            "excluded_ips": ["192.168.1.1", "192.168.1.50"],  # 2 conflicts
            "restricted_actions": [],
            "max_iterations": 5,  # 1 more conflict
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(conflict_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        # 3 conflicts = 15% penalty
        assert result.confidence_score < 0.85


# ============================================================================
# TESTS: Convenience Function
# ============================================================================

class TestConvenienceFunction:
    """Test the interpret_roe convenience function."""

    @patch('litellm.completion')
    def test_interpret_roe_function(self, mock_completion, valid_roe_dict, mock_litellm_valid_response):
        """interpret_roe function should work correctly."""
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(mock_litellm_valid_response)
            ))]
        )
        
        result = interpret_roe(valid_roe_dict)
        
        assert result.is_valid is True
        assert result.confidence_score >= 0.95


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch('litellm.completion')
    def test_empty_scope_handling(self, mock_completion, valid_roe_dict):
        """Empty scope extraction should be handled."""
        empty_response = {
            "scope_cidrs": [],
            "scope_domains": [],
            "scope_urls": [],
            "excluded_ips": [],
            "restricted_actions": [],
            "max_iterations": 50,
            "max_retries": 3,
            "cloud_allowed": False,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(empty_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(valid_roe_dict)
        
        assert result.is_valid is True
        assert len(result.extracted_policy.scope_cidrs) == 0

    @patch('litellm.completion')
    def test_complex_roe_handling(self, mock_completion, complex_roe_dict):
        """Complex ROE with multiple scopes should be handled."""
        complex_response = {
            "scope_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
            "scope_domains": ["api.company.com", "admin.company.com"],
            "scope_urls": ["https://api.company.com/v1", "https://admin.company.com"],
            "excluded_ips": ["10.0.1.1", "10.0.1.5"],
            "restricted_actions": ["MODIFY_DATA", "DELETE_DATA", "ENCRYPT_DATA"],
            "max_iterations": 100,
            "max_retries": 5,
            "cloud_allowed": True,
        }
        
        mock_completion.return_value = MagicMock(
            choices=[MagicMock(message=MagicMock(
                content=json.dumps(complex_response)
            ))]
        )
        
        interpreter = ROEInterpreter()
        result = interpreter.interpret(complex_roe_dict)
        
        assert result.is_valid is True
        assert len(result.extracted_policy.scope_cidrs) == 2
        assert len(result.extracted_policy.restricted_actions) == 3
