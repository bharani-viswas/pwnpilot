"""
ROE Interpreter - AI-Driven Policy Extraction from ROE Files

Uses LLM (Bedrock Claude via LiteLLM) to interpret ROE documents and extract:
- Refined scope definitions (CIDRs, domains, URLs from description)
- Policy configurations (iterations, retries, timeouts)
- Risk assessments and confidence scores
- Hallucination detection and conflict identification

Security features:
- Anti-injection validation (compare extracted vs. original ROE)
- Hallucination detection with confidence thresholds
- Conflict detection (excluded IPs outside scope, etc.)
- Unknown action detection
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pydantic import BaseModel, Field, ValidationError

try:
    import litellm
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False


@dataclass
class ExtractedPolicy:
    """Policy extracted from ROE by LLM"""
    
    scope_cidrs: List[str]
    scope_domains: List[str]
    scope_urls: List[str]
    excluded_ips: List[str]
    restricted_actions: List[str]
    max_iterations: int
    max_retries: int
    timeout_seconds: int
    cloud_allowed: bool
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class InterpretationResult:
    """Result of ROE interpretation by AI"""
    
    is_valid: bool
    extracted_policy: Optional[ExtractedPolicy]
    confidence_score: float  # 0.0-1.0, < 0.85 indicates hallucination risk
    warnings: List[str]
    concerns: List[str]
    hallucination_risks: List[str]
    injection_detected: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary with policy as dict"""
        return {
            'is_valid': self.is_valid,
            'extracted_policy': self.extracted_policy.to_dict() if self.extracted_policy else None,
            'confidence_score': self.confidence_score,
            'warnings': self.warnings,
            'concerns': self.concerns,
            'hallucination_risks': self.hallucination_risks,
            'injection_detected': self.injection_detected,
            'error_message': self.error_message,
        }


class ROEInterpreter:
    """
    AI-powered ROE interpreter using LLM for policy extraction.
    
    Implements multiple security layers:
    1. Injection detection - validate extracted content against ROE source
    2. Hallucination detection - confidence scoring and validation
    3. Conflict detection - logical inconsistencies (excluded outside scope, etc.)
    """
    
    # LLM configuration
    LLM_MODEL = "bedrock/anthropic.claude-3-sonnet-20240229-v1:0"
    HALLUCINATION_THRESHOLD = 0.85
    MAX_TOKENS = 2000
    TEMPERATURE = 0.3  # Lower temp = more deterministic
    
    # Allowed values for validation
    ALLOWED_ACTIONS = {
        "MODIFY_DATA", "DELETE_DATA", "ENCRYPT_DATA",
        "STOP_SERVICES", "MODIFY_CREDENTIALS", "EXFILTRATE_DATA"
    }
    
    def __init__(self, litellm_api_key: Optional[str] = None, model_name: Optional[str] = None, 
                 api_base_url: Optional[str] = None):
        """Initialize ROE interpreter with optional API key and model configuration."""
        if not LITELLM_AVAILABLE:
            raise ImportError("litellm package required: pip install litellm")
        
        # Use provided configuration or defaults
        self.model_name = model_name or "openai/Bedrock-Claude-4.5-Sonnet"
        self.api_base_url = api_base_url or ""
        
        if litellm_api_key:
            litellm.api_key = litellm_api_key
        
        self.warnings: List[str] = []
        self.concerns: List[str] = []
        self.hallucination_risks: List[str] = []
    
    def interpret(self, roe_dict: dict) -> InterpretationResult:
        """
        Interpret a validated ROE dictionary using LLM.
        
        Args:
            roe_dict: Validated ROE configuration from ROESchema
        
        Returns:
            InterpretationResult with extracted policies and confidence scores
        """
        self.warnings = []
        self.concerns = []
        self.hallucination_risks = []
        
        try:
            # Step 1: Extract basic info from ROE
            roe_json = json.dumps(roe_dict, indent=2)
            
            # Step 2: Call LLM for policy interpretation
            extracted = self._call_llm_for_extraction(roe_json)
            
            # Step 3: Validate extracted policies against ROE (injection detection)
            injection_detected, injection_warnings = self._detect_injection(
                extracted, roe_dict
            )
            
            if injection_detected:
                self.concerns.extend(injection_warnings)
            
            # Step 4: Detect hallucinations (unknown fields, impossible values)
            hallucination_score, hallucination_list = self._detect_hallucinations(
                extracted, roe_dict
            )
            
            self.hallucination_risks.extend(hallucination_list)
            
            # Step 5: Detect conflicts (logical inconsistencies)
            conflicts = self._detect_conflicts(extracted)
            self.concerns.extend(conflicts)
            
            # Calculate final confidence score
            confidence = self._calculate_confidence(
                injection_detected,
                hallucination_score,
                len(conflicts)
            )
            
            # Step 6: If confidence too low, flag for manual review
            if confidence < self.HALLUCINATION_THRESHOLD:
                self.concerns.append(
                    f"⚠️ LOW CONFIDENCE ({confidence:.2%}): Manual review recommended before approval"
                )
            
            result = InterpretationResult(
                is_valid=True,
                extracted_policy=extracted,
                confidence_score=confidence,
                warnings=self.warnings,
                concerns=self.concerns,
                hallucination_risks=self.hallucination_risks,
                injection_detected=injection_detected,
                error_message=None,
            )
            
            return result
            
        except Exception as e:
            return InterpretationResult(
                is_valid=False,
                extracted_policy=None,
                confidence_score=0.0,
                warnings=self.warnings,
                concerns=self.concerns,
                hallucination_risks=self.hallucination_risks,
                injection_detected=False,
                error_message=f"Interpretation failed: {str(e)}",
            )
    
    def _call_llm_for_extraction(self, roe_json: str) -> ExtractedPolicy:
        """Call LLM to extract structured policy from ROE JSON."""
        
        prompt = f"""You are a security policy expert. Analyze this ROE (Rules of Engagement) document 
and extract ONLY the security policies that are EXPLICITLY STATED. 
Do NOT invent or assume any policies not mentioned.

ROE Document:
{roe_json}

Extract and return ONLY a JSON object with these fields:
{{
  "scope_cidrs": [list of CIDR blocks mentioned, or empty array],
  "scope_domains": [list of domains mentioned, or empty array],
  "scope_urls": [list of URLs mentioned, or empty array],
  "excluded_ips": [list of excluded IPs mentioned, or empty array],
  "restricted_actions": [list of actions from ROE, or empty array],
  "max_iterations": [number from policy.max_iterations],
  "max_retries": [number from policy.max_retries],
  "timeout_seconds": [number from policy.timeout_seconds],
  "cloud_allowed": [boolean from policy.cloud_allowed]
}}

CRITICAL RULES:
1. Only extract values EXPLICITLY in the ROE - do NOT invent values
2. For restricted_actions, only include actions that are explicitly listed
3. For numbers (iterations, retries, timeout), use the exact values from ROE
4. If a field is not mentioned, use null or empty array
5. Return ONLY valid JSON, no explanations"""
        
        try:
            response = litellm.completion(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.TEMPERATURE,
                max_tokens=self.MAX_TOKENS,
                api_base=self.api_base_url if self.api_base_url else None,
            )
            
            # Extract JSON from response
            response_text = response.choices[0].message.content
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            
            if not json_match:
                raise ValueError("LLM did not return valid JSON")
            
            extracted_json = json.loads(json_match.group())
            
            # Convert to ExtractedPolicy
            policy = ExtractedPolicy(
                scope_cidrs=extracted_json.get('scope_cidrs', []) or [],
                scope_domains=extracted_json.get('scope_domains', []) or [],
                scope_urls=extracted_json.get('scope_urls', []) or [],
                excluded_ips=extracted_json.get('excluded_ips', []) or [],
                restricted_actions=extracted_json.get('restricted_actions', []) or [],
                max_iterations=extracted_json.get('max_iterations', 50),
                max_retries=extracted_json.get('max_retries', 3),
                timeout_seconds=extracted_json.get('timeout_seconds', 3600),
                cloud_allowed=extracted_json.get('cloud_allowed', False),
            )
            
            return policy
            
        except Exception as e:
            raise ValueError(f"LLM extraction failed: {str(e)}")
    
    def _detect_injection(self, extracted: ExtractedPolicy, roe_dict: dict) -> Tuple[bool, List[str]]:
        """
        Detect injection attempts by comparing extracted vs. original ROE.
        
        Returns:
            (injection_detected, warnings_list)
        """
        warnings = []
        detected = False
        
        # Check if extracted scope is within the original scope
        original_cidrs = set(roe_dict.get('scope', {}).get('cidrs', '').split(','))
        original_cidrs = {c.strip() for c in original_cidrs if c.strip()}
        
        extracted_cidrs = set(extracted.scope_cidrs or [])
        
        # Warn if extracted scope is significantly different from original
        if original_cidrs and extracted_cidrs and original_cidrs != extracted_cidrs:
            warnings.append(f"⚠️ Extracted CIDRs differ from ROE: {extracted_cidrs - original_cidrs}")
        
        # Check for unknown actions (not in ROE)
        original_actions = set(roe_dict.get('scope', {}).get('restricted_actions', '').split(','))
        original_actions = {a.strip() for a in original_actions if a.strip()}
        
        extracted_actions = set(extracted.restricted_actions or [])
        
        unknown_actions = extracted_actions - original_actions
        if unknown_actions:
            warnings.append(f"⚠️ Injection detected: Unknown actions extracted: {unknown_actions}")
            detected = True
        
        # Check for invalid action values
        invalid_actions = extracted_actions - self.ALLOWED_ACTIONS
        if invalid_actions:
            warnings.append(f"⚠️ Injection detected: Invalid action values: {invalid_actions}")
            detected = True
        
        return detected, warnings
    
    def _detect_hallucinations(self, extracted: ExtractedPolicy, roe_dict: dict) -> Tuple[float, List[str]]:
        """
        Detect hallucinations (LLM making up values not in ROE).
        
        Returns:
            (confidence_score, hallucination_list)
        """
        hallucinations = []
        confidence = 1.0
        
        # Check if max_iterations was invented (should be in ROE)
        policy_max_iter = roe_dict.get('policy', {}).get('max_iterations')
        if extracted.max_iterations != policy_max_iter:
            hallucinations.append(
                f"⚠️ Hallucination: max_iterations {extracted.max_iterations} != ROE {policy_max_iter}"
            )
            confidence -= 0.15
        
        # Check if timeout_seconds was invented
        policy_timeout = roe_dict.get('policy', {}).get('timeout_seconds')
        if extracted.timeout_seconds != policy_timeout:
            hallucinations.append(
                f"⚠️ Hallucination: timeout_seconds {extracted.timeout_seconds} != ROE {policy_timeout}"
            )
            confidence -= 0.15
        
        # Check if cloud_allowed was invented
        policy_cloud = roe_dict.get('policy', {}).get('cloud_allowed')
        if extracted.cloud_allowed != policy_cloud:
            hallucinations.append(
                f"⚠️ Hallucination: cloud_allowed {extracted.cloud_allowed} != ROE {policy_cloud}"
            )
            confidence -= 0.15
        
        # Check for nonsensical values (e.g., negative numbers, out of range)
        if extracted.max_iterations <= 0 or extracted.max_iterations > 1000:
            hallucinations.append(
                f"⚠️ Hallucination: max_iterations {extracted.max_iterations} out of range [1-1000]"
            )
            confidence -= 0.10
        
        if extracted.timeout_seconds < 300 or extracted.timeout_seconds > 86400:
            hallucinations.append(
                f"⚠️ Hallucination: timeout_seconds {extracted.timeout_seconds} unrealistic"
            )
            confidence -= 0.10
        
        return max(0.0, confidence), hallucinations
    
    def _detect_conflicts(self, extracted: ExtractedPolicy) -> List[str]:
        """
        Detect logical conflicts in extracted policies.
        
        Returns:
            List of conflict warnings
        """
        conflicts = []
        
        # Check if excluded IPs are within scope CIDRs
        if extracted.excluded_ips and extracted.scope_cidrs:
            import ipaddress
            try:
                scope_cidrs = [ipaddress.IPv4Network(c) for c in extracted.scope_cidrs]
                for excluded_ip_str in extracted.excluded_ips:
                    try:
                        excluded_ip = ipaddress.IPv4Address(excluded_ip_str)
                        in_scope = any(excluded_ip in cidr for cidr in scope_cidrs)
                        if not in_scope:
                            conflicts.append(
                                f"⚠️ Conflict: Excluded IP {excluded_ip_str} not in scope CIDRs"
                            )
                    except ipaddress.AddressValueError:
                        pass
            except Exception:
                pass
        
        # Check if restricted actions are valid
        invalid_actions = set(extracted.restricted_actions or []) - self.ALLOWED_ACTIONS
        if invalid_actions:
            conflicts.append(
                f"⚠️ Conflict: Invalid restricted actions: {invalid_actions}"
            )
        
        # Check if max_iterations is unreasonably low
        if extracted.max_iterations < 10:
            conflicts.append(
                f"⚠️ Conflict: max_iterations {extracted.max_iterations} is very low (typical: 20-100)"
            )
        
        return conflicts
    
    def _calculate_confidence(
        self,
        injection_detected: bool,
        hallucination_score: float,
        num_conflicts: int
    ) -> float:
        """Calculate final confidence score for the interpretation."""
        
        confidence = hallucination_score
        
        # Penalty for injection detection
        if injection_detected:
            confidence -= 0.30
        
        # Penalty for each conflict
        confidence -= (num_conflicts * 0.05)
        
        # Clamp to [0.0, 1.0]
        return max(0.0, min(1.0, confidence))


def interpret_roe(roe_dict: dict, litellm_api_key: Optional[str] = None) -> InterpretationResult:
    """
    Convenience function to interpret a ROE dictionary.
    
    Args:
        roe_dict: Validated ROE configuration
        litellm_api_key: Optional API key (uses environment by default)
    
    Returns:
        InterpretationResult with extracted policies
    """
    interpreter = ROEInterpreter(litellm_api_key=litellm_api_key)
    return interpreter.interpret(roe_dict)
