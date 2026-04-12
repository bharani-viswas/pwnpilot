from __future__ import annotations

import pytest
from pydantic import ValidationError

from pwnpilot.data.roe_validator import ROESchema


def _base_roe() -> dict:
    return {
        "engagement": {
            "name": "test-engagement-001",
            "authorizer": "test@company.com",
            "description": "This is a test engagement with sufficient description length for validation purposes and must contain at least 100 character",
            "valid_hours": 24,
        },
        "scope": {
            "target_profile": "default",
            "cidrs": "",
            "domains": "",
            "urls": "http://localhost:3000",
            "excluded_ips": "",
            "restricted_actions": "",
        },
        "policy": {
            "cloud_allowed": False,
            "max_iterations": 20,
            "max_retries": 3,
            "timeout_seconds": 3600,
        },
    }


def test_local_profile_allows_localhost_domain() -> None:
    roe = _base_roe()
    roe["scope"]["target_profile"] = "local"
    roe["scope"]["domains"] = "localhost"

    parsed = ROESchema(**roe)
    assert parsed.scope.domains == "localhost"


def test_default_profile_rejects_localhost_domain() -> None:
    roe = _base_roe()
    roe["scope"]["domains"] = "localhost"

    with pytest.raises(ValidationError):
        ROESchema(**roe)
