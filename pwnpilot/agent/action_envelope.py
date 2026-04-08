"""
Action Envelope — structured LLM output parser and ActionRequest schema enforcer.

The ActionEnvelope is the contract between raw LLM output and the typed ActionRequest.
No LLM output is ever executed without passing through this parser (ADR-002).

Flow:
  LLM JSON response
    → ActionEnvelope.parse()        — extract and validate the envelope structure
    → ActionRequest constructor     — Pydantic AfterValidator on params
    → PolicyEngine.evaluate()       — gate check
"""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ValidationError

import structlog

from pwnpilot.data.models import ActionRequest, ActionType, RiskLevel

log = structlog.get_logger(__name__)


class ActionEnvelopeError(Exception):
    """Raised when the LLM output cannot be parsed into a valid ActionEnvelope."""


class ActionEnvelope(BaseModel):
    """
    The structured output format expected from the LLM.  All fields must be present
    and type-valid for an ActionRequest to be constructed.
    """
    action_type: str
    tool_name: str
    target: str
    params: dict[str, Any] = {}
    rationale: str
    estimated_risk: str

    def to_action_request(self, engagement_id: UUID) -> ActionRequest:
        """Convert the envelope to a typed, validated ActionRequest."""
        try:
            action_type = ActionType(self.action_type)
            risk_level = RiskLevel(self.estimated_risk)
        except ValueError as exc:
            raise ActionEnvelopeError(f"Invalid enum value in envelope: {exc}") from exc

        try:
            return ActionRequest(
                engagement_id=engagement_id,
                action_type=action_type,
                tool_name=self.tool_name,
                params={**self.params, "target": self.target},
                risk_level=risk_level,
            )
        except ValidationError as exc:
            raise ActionEnvelopeError(
                f"ActionRequest construction failed: {exc}"
            ) from exc


def parse_action_envelope(raw_json: str) -> ActionEnvelope:
    """
    Parse the raw JSON string from the LLM into a validated ActionEnvelope.
    Raises ActionEnvelopeError on any structural or type violation.
    """
    # Strip markdown fences
    text = raw_json.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ActionEnvelopeError(
            f"LLM output is not valid JSON: {exc}\nRaw: {text[:300]!r}"
        ) from exc

    if not isinstance(data, dict):
        raise ActionEnvelopeError(
            f"Expected a JSON object; got {type(data).__name__}"
        )

    try:
        envelope = ActionEnvelope(**data)
    except ValidationError as exc:
        raise ActionEnvelopeError(
            f"ActionEnvelope schema validation failed: {exc}"
        ) from exc

    log.debug(
        "action_envelope.parsed",
        tool=envelope.tool_name,
        action_type=envelope.action_type,
        risk=envelope.estimated_risk,
    )
    return envelope
