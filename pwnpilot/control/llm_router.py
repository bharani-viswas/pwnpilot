"""
LLM Router — unified multi-provider inference with redaction, retry, circuit breaker,
and policy-gated fallback.

Routing logic (ADR-004):
1. Attempt primary model (via LiteLLM) up to 3 times with exponential backoff.
2. After 3 consecutive failures, open circuit breaker for 60s.
3. If circuit is open: evaluate cloud fallback policy gate.
4. If fallback denied: raise PolicyDeniedError; orchestrator halts.
5. Before cloud dispatch: run redactor.scrub() on the prompt.
6. Log all routing decisions to audit store.

LiteLLM unified API supports: OpenAI, Claude, Gemini, Ollama, vLLM, LocalAI, 
Mistral, Cohere, LLaMA2, and 100+ other providers with zero code changes.
Just configure: model_name, api_key, api_base_url

Circuit breaker states: CLOSED → OPEN → HALF_OPEN → CLOSED
"""
from __future__ import annotations

import json
import os
import time
from enum import Enum
from typing import Any

import litellm
import structlog

from pwnpilot.secrets.redactor import Redactor

log = structlog.get_logger(__name__)

# Timeouts and retry config
_PRIMARY_TIMEOUT: float = 120.0
_FALLBACK_TIMEOUT: float = 60.0
_MAX_RETRIES: int = 3
_BACKOFF_BASE: float = 1.0
_BACKOFF_MAX: float = 8.0
_CIRCUIT_OPEN_DURATION: float = 60.0


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class PolicyDeniedError(Exception):
    """Raised when fallback is blocked by policy."""


class LLMRouterError(Exception):
    """Raised when all LLM paths are exhausted."""


class LLMRouter:
    """
    Routes LLM inference requests across any provider via LiteLLM.
    
    Supports: OpenAI, Claude, Gemini, Ollama, vLLM, LocalAI, and 100+ providers.
    Just configure model_name, api_key, and optional api_base_url.

    Args:
        model_name:           Primary model identifier (e.g. "gpt-4", "claude-3-sonnet-20240229", "ollama/llama2")
        api_key:              API key for primary model (can be empty for local models)
        api_base_url:         Optional custom API endpoint (e.g. "http://localhost:8000/v1")
        fallback_model_name:  Fallback model if primary exhausted and policy allows
        fallback_api_key:     API key for fallback model
        fallback_api_base_url: Custom base URL for fallback model
        cloud_allowed_fn:     Callable() -> bool: returns True if fallback is policy-allowed
        redactor:             Redactor instance for prompt scrubbing before cloud dispatch
        audit_fn:             Optional audit logging callback(event_type, payload)
        timeout_seconds:      Request timeout in seconds
        max_retries:          Max retry attempts per model
    """

    def __init__(
        self,
        model_name: str = "ollama/llama3",
        api_key: str = "",
        api_base_url: str = "",
        fallback_model_name: str = "gpt-4o-mini",
        fallback_api_key: str = "",
        fallback_api_base_url: str = "",
        cloud_allowed_fn: Any = None,
        redactor: Redactor | None = None,
        audit_fn: Any = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
    ) -> None:
        self._model_name = model_name
        self._api_key = api_key or os.environ.get("LITELLM_API_KEY", "")
        self._api_base_url = api_base_url
        
        self._fallback_model_name = fallback_model_name
        self._fallback_api_key = fallback_api_key or os.environ.get("LITELLM_FALLBACK_API_KEY", "")
        self._fallback_api_base_url = fallback_api_base_url
        
        self._cloud_allowed = cloud_allowed_fn or (lambda: False)
        self._redactor = redactor or Redactor()
        self._audit = audit_fn
        self._timeout = timeout_seconds
        self._max_retries = max_retries

        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._circuit_open_at: float = 0.0
        self._consecutive_failures: int = 0
        
        # Suppress litellm debug output
        litellm.suppress_debug_info = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a completion request. Returns the model response string.
        Tries primary model first; falls back to fallback model if policy permits.
        """
        routing = "primary"
        self._check_circuit()

        if self._circuit_state != CircuitState.OPEN:
            try:
                response = self._complete_with_retry(
                    self._model_name,
                    self._api_key,
                    self._api_base_url,
                    system_prompt,
                    user_prompt,
                )
                self._on_success()
                if self._audit:
                    self._audit("LLMRouted", {"routing": routing, "model": self._model_name})
                return response
            except Exception as exc:
                self._on_failure()
                log.warning("llm_router.primary_failed", exc=str(exc), model=self._model_name)

        # Fallback routing
        routing = "fallback"
        if not self._cloud_allowed():
            raise PolicyDeniedError(
                "Fallback LLM routing is not permitted by current policy."
            )

        if not self._fallback_model_name:
            raise LLMRouterError("No fallback model configured and primary model is unavailable.")

        # Redact prompt before fallback dispatch
        safe_system = self._redactor.scrub(system_prompt)
        safe_user = self._redactor.scrub(user_prompt)

        try:
            response = self._complete_with_retry(
                self._fallback_model_name,
                self._fallback_api_key,
                self._fallback_api_base_url,
                safe_system,
                safe_user,
            )
            if self._audit:
                self._audit("LLMRouted", {"routing": routing, "model": self._fallback_model_name})
            return response
        except Exception as exc:
            raise LLMRouterError(f"Fallback model also failed: {exc}") from exc

    def plan(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Ask the LLM to produce a PlannerProposal dict given *context*.
        The response is parsed as JSON and returned as a dict.
        Enhanced to leverage findings for intelligent prioritization and tool parameter schemas.
        """
        # Extract tool parameter schemas if available
        tool_schemas = context.get("tool_parameter_schemas", {})
        schemas_section = ""
        if tool_schemas:
            schemas_section = self._format_tool_schemas(tool_schemas)
        
        system = f"""You are an intelligent penetration testing orchestrator for automated security assessments.

Your role: Analyze engagement state and decide the NEXT action that provides maximum value.

Decision Logic (Priority Order):
0. FOLLOW TARGET STRATEGY: If target_strategy_progress.current_step exists, prioritize that step before jumping ahead
1. VERIFY HIGH-RISK FINDINGS: If unverified high/critical findings exist → attempt verification
2. DEEPEN EXPLOITATION: If verified vulnerabilities exist → attempt exploitation or post-exploitation
3. EXPAND DISCOVERY: If few findings → expand reconnaissance to new targets/ranges
4. VALIDATE FINDINGS: Use different tools to confirm/eliminate findings

Context Available:
- discovered_hosts: List of IPs/domains with services detected
- findings_count: Total findings, unverified, and verified counts
- unverified_high_findings: Specific high/critical findings needing verification
- previous_actions: Last 10 actions (avoid duplicates)
- available_tools: Runtime-enabled and trusted tool names
- tools_catalog: Capability metadata for each available tool
- tool_parameter_schemas: CANONICAL parameter specifications for each tool (SEE BELOW)
- temporarily_unavailable_tools: tools that recently failed due to runtime availability errors
- target_strategy: deterministic step sequence and tool mapping for this target family
- target_strategy_progress: completed steps and current recommended step

TOOL PARAMETER REFERENCE:
{schemas_section}

CONSTRAINTS:
- You MUST choose tool_name only from available_tools.
- You MUST use EXACT parameter names from the schema (not aliases or variations).
- You MUST respect parameter types: strings vs arrays vs booleans as specified.
- For enum parameters, ONLY use values listed in the schema's enum field.
- You MUST prefer tools whose supported_target_types and required_params fit the target and action.
- If an unavailable or incompatible tool would be ideal, pick the closest available alternative and explain why in rationale.
- If a tool appears in temporarily_unavailable_tools, do NOT propose it in this iteration.
- If rejection_reason indicates a missing binary/tool unavailable error, you MUST select a different tool.
- If target_strategy_progress.current_step exists, prefer a tool from that step's preferred_tools,
  then fallback_tools only if preferred tools are unavailable.
- Do not skip endpoint/route discovery steps for web targets unless that step is marked completed.

Strategy Examples:
- "Found CORS vulnerability" → "Test PUT/DELETE requests to verify exploitability"
- "SSH service discovered" → "Attempt credential brute-force or key enumeration"
- "Empty recon" → "Run initial network scan to discover services"
- "HTTP methods testing failed" → "Try OPTIONS request or test specific deprecated methods"
- "Found 5 vulnerabilities" → "Prioritize the highest severity ones first"

DO NOT:
- Repeat actions already in previous_actions (check the list)
- Try the exact same tool twice on the same target
- Ignore high-severity findings
- Use parameter names that differ from the canonical schema (e.g., use 'sV' not 'service_detection')

MUST return ONLY valid JSON matching PlannerProposal schema:
{{
  "action_type": "recon_passive|active_scan|exploit|post_exploit",
  "tool_name": "tool_name",
  "target": "IP or domain or URL",
  "params": {{"key": "value", ...}},
  "rationale": "Why this action will advance the engagement",
  "estimated_risk": "low|medium|high|critical"
}}"""
        
        user = json.dumps(context, default=str)
        raw = self.complete(system, user)
        return self._parse_json(raw, "PlannerProposal")

    def reflect(self, context: dict[str, Any]) -> dict[str, Any]:
        """Return a corrective pivot-or-terminate decision for reject churn."""
        system = """You are a stabilization reflector for an autonomous pentest agent.

Given repeated validator rejects, choose exactly one:
1) pivot: recommend a different tool family to continue safely, or
2) terminate: stop autonomous loop and request report finalization.

Rules:
- Choose terminate when repeated rejects indicate policy/capability dead-end.
- If choosing pivot, candidate_tools must exclude rejected_tool.
- Output ONLY valid JSON with this schema:
{
    "decision": "pivot|terminate",
    "rationale": "short reason",
    "candidate_tools": ["toolA", "toolB"],
    "termination_reason": "reflector_terminate"
}
"""
        raw = self.complete(system, json.dumps(context, default=str))
        return self._parse_json(raw, "ReflectorDecision")

    def _format_tool_schemas(self, schemas: dict[str, Any]) -> str:
        """Format tool schemas into a readable reference section."""
        if not schemas:
            return "(No tool schemas available)"
        
        lines = []
        for tool_name in sorted(schemas.keys()):
            tool_schema = schemas[tool_name]
            lines.append(f"#### {tool_name}")
            
            desc = tool_schema.get("description", "")
            if desc:
                lines.append(f"{desc}")
            
            risk = tool_schema.get("risk_class", "")
            if risk:
                lines.append(f"Risk: {risk}")
            
            params = tool_schema.get("parameters", {})
            if params:
                required = tool_schema.get("required_params", [])
                lines.append("Parameters:")
                
                for param_name, param_doc in sorted(params.items()):
                    req_marker = "*REQUIRED*" if param_name in required else "optional"
                    param_type = param_doc.get("type", "unknown")
                    desc = param_doc.get("description", "")
                    
                    lines.append(f"  - `{param_name}` ({param_type}, {req_marker}): {desc}")
                    
                    if "enum" in param_doc:
                        enum_vals = param_doc["enum"]
                        lines.append(f"    Values: {', '.join(map(str, enum_vals))}")
                    
                    if "default" in param_doc:
                        lines.append(f"    Default: {param_doc['default']}")
            
            lines.append("")
        
        return "\n".join(lines)

    def validate(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Ask the LLM to produce a ValidationResult dict given *context*.
        Enhanced to assess finding confidence and detect false positives.
        """
        system = """You are a penetration testing risk validator and findings analyst.

Your tasks:
1. Assess the risk level of the proposed action
2. If a finding is provided, assess its likelihood of being a real vulnerability vs false positive

For findings assessment:
- Real vulnerabilities: Typically reproducible, match known exploits, consistent across tools
- False positives: Single tool detection, unrealistic scenarios, contradicting evidence

For actions assessment:
- Escalate risk if multiple high-severity findings or confirmed vulnerabilities exist
- Never downgrade risk level from proposal
- Reject if action violates policy or scope

Return a JSON object matching ValidationResult schema:
{
  "verdict": "approve|reject",
  "risk_override": "low|medium|high|critical" or null,
    "rationale": "Why this decision",
    "rejection_reason_code": "optional normalized code when verdict=reject",
    "rejection_reason_detail": "optional reject detail",
    "rejection_class": "optional class: capability|target|policy|low_value|duplicate"
}"""
        user = json.dumps(context, default=str)
        raw = self.complete(system, user)
        return self._parse_json(raw, "ValidationResult")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _complete_with_retry(
        self,
        model_name: str,
        api_key: str,
        api_base_url: str,
        system: str,
        user: str,
    ) -> str:
        """Call the model with exponential backoff retry logic."""
        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                return self._litellm_complete(model_name, api_key, api_base_url, system, user)
            except Exception as exc:
                last_exc = exc
                wait = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
                log.debug(
                    "llm_router.retry",
                    model=model_name,
                    attempt=attempt + 1,
                    wait=wait,
                    exc=str(exc),
                )
                time.sleep(wait)
        raise last_exc or RuntimeError(f"Model {model_name} failed after {self._max_retries} retries.")

    def _litellm_complete(
        self,
        model_name: str,
        api_key: str,
        api_base_url: str,
        system: str,
        user: str,
    ) -> str:
        """Call LiteLLM's completion endpoint with unified provider support."""
        # Set up environment for this request
        if api_key:
            os.environ["LITELLM_API_KEY"] = api_key
        
        kwargs = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "timeout": self._timeout,
            "max_retries": 1,  # We handle retries ourselves
        }
        
        # Add custom base URL if provided (for Ollama, vLLM, LocalAI, etc.)
        if api_base_url:
            kwargs["api_base"] = api_base_url
        
        response = litellm.completion(**kwargs)
        return response.choices[0].message.content or ""

    def _check_circuit(self) -> None:
        """Check circuit breaker state and transition if needed."""
        now = time.monotonic()
        if self._circuit_state == CircuitState.OPEN:
            if now - self._circuit_open_at >= _CIRCUIT_OPEN_DURATION:
                log.info("llm_router.circuit_half_open")
                self._circuit_state = CircuitState.HALF_OPEN

    def _on_success(self) -> None:
        """Handle successful model call."""
        self._consecutive_failures = 0
        if self._circuit_state != CircuitState.CLOSED:
            log.info("llm_router.circuit_closed")
            self._circuit_state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        """Handle failed model call and update circuit state."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._max_retries:
            log.warning(
                "llm_router.circuit_open",
                failures=self._consecutive_failures,
                model=self._model_name,
            )
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_at = time.monotonic()

    @staticmethod
    def _parse_json(raw: str, schema_name: str) -> dict[str, Any]:
        """Extract and parse the first JSON object from the LLM response."""
        # Strip markdown code fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM did not return valid JSON for {schema_name}: {exc}\nRaw: {raw[:500]!r}"
            ) from exc
