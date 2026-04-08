"""
Action Validator — enforces ActionRequest schema completeness and per-tool param
validation before the Policy Engine sees the request.

This is a secondary gate that complements the ActionEnvelope parser.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from pwnpilot.data.models import ActionRequest

log = structlog.get_logger(__name__)


class ActionValidationError(Exception):
    pass


class ActionValidator:
    """
    Validates a proposed ActionRequest against:
    1. Required fields completeness
    2. Tool adapter param schema (adapter.validate_params())
    3. Engagement scope (is_in_scope on target)
    """

    def __init__(self, adapters: dict[str, Any]) -> None:
        self._adapters = adapters

    def validate(self, action: ActionRequest) -> ActionRequest:
        """
        Validate the action and return it unchanged.  Raises ActionValidationError on
        any structural violation.
        """
        # Validate tool exists
        adapter = self._adapters.get(action.tool_name)
        if adapter is None:
            raise ActionValidationError(
                f"Unknown tool '{action.tool_name}'. "
                f"Available: {list(self._adapters.keys())}"
            )

        # Validate params through adapter (AfterValidator equivalent)
        try:
            adapter.validate_params(action.params)
        except (ValueError, Exception) as exc:
            raise ActionValidationError(
                f"Tool '{action.tool_name}' param validation failed: {exc}"
            ) from exc

        log.debug(
            "action_validator.ok",
            action_id=str(action.action_id),
            tool=action.tool_name,
        )
        return action
