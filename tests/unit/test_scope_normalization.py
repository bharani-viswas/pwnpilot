from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pwnpilot.control.engagement import EngagementService
from pwnpilot.data.models import Engagement, EngagementScope


def _engagement(scope: EngagementScope) -> Engagement:
    now = datetime.now(timezone.utc)
    return Engagement(
        engagement_id=uuid4(),
        name="local-scope-test",
        operator_id="operator",
        scope=scope,
        roe_document_hash="0" * 64,
        authoriser_identity="authorizer@example.com",
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(hours=1),
    )


def test_localhost_host_equivalence_matches_url_scope() -> None:
    svc = EngagementService(
        _engagement(
            EngagementScope(
                scope_urls=["http://localhost:3000"],
                scope_domains=[],
                scope_cidrs=[],
            )
        )
    )

    assert svc.is_in_scope("localhost") is True
    assert svc.is_in_scope("127.0.0.1") is True
