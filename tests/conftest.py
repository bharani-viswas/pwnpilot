"""
Pytest fixtures and configuration for PwnPilot tests.

Shared fixtures for database testing, ROE data, models, etc.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from pwnpilot.data.models import (
    ROEFile,
    EngagementPolicy,
    ROEApprovalRecord,
    Engagement,
    EngagementScope,
)


# ---------------------------------------------------------------------------
# ROE File Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_roe_yaml_content():
    """Provide a valid ROE YAML file content."""
    return """
scope:
  cidrs:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  domains:
    - "example.com"
    - "test.local"
  urls:
    - "https://api.example.com/v1"
  excludedIps:
    - "192.168.1.1"
    - "10.0.0.1"

actions:
  - MODIFY_DATA
  - DELETE_DATA
  - EXFILTRATE_DATA

limits:
  maxIterations: 5
  maxRetries: 3
  timeoutSeconds: 300
  cloudAllowed: false

authorisation:
  operator: "security-team@example.com"
  validFrom: "2026-04-12T00:00:00Z"
  validUntil: "2026-05-12T23:59:59Z"
"""


@pytest.fixture
def sample_roe_file(sample_roe_yaml_content):
    """Create a sample ROEFile model."""
    import hashlib
    
    content_hash = hashlib.sha256(sample_roe_yaml_content.encode()).hexdigest()
    
    return ROEFile(
        roe_id=uuid4(),
        filename="engagement_roe_2026_04_12.yaml",
        content_hash=content_hash,
        content_yaml=sample_roe_yaml_content,
        uploaded_by="security-team@example.com",
        uploaded_at=datetime.now(timezone.utc),
        version=1,
        is_active=True,
    )


@pytest.fixture
def sample_roe_file_v2(sample_roe_yaml_content):
    """Create a second version of ROEFile."""
    import hashlib
    
    updated_content = sample_roe_yaml_content.replace("maxIterations: 5", "maxIterations: 10")
    content_hash = hashlib.sha256(updated_content.encode()).hexdigest()
    
    return ROEFile(
        roe_id=uuid4(),
        filename="engagement_roe_2026_04_12_v2.yaml",
        content_hash=content_hash,
        content_yaml=updated_content,
        uploaded_by="security-team@example.com",
        uploaded_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        version=2,
        is_active=True,
    )


# ---------------------------------------------------------------------------
# Engagement Policy Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_engagement_policy(sample_roe_file):
    """Create a sample EngagementPolicy model."""
    return EngagementPolicy(
        policy_id=uuid4(),
        engagement_id=uuid4(),
        roe_id=sample_roe_file.roe_id,
        scope_cidrs=["192.168.1.0/24", "10.0.0.0/8"],
        scope_domains=["example.com", "test.local"],
        scope_urls=["https://api.example.com/v1"],
        excluded_ips=["192.168.1.1", "10.0.0.1"],
        restricted_actions=["MODIFY_DATA", "DELETE_DATA", "EXFILTRATE_DATA"],
        max_iterations=5,
        max_retries=3,
        timeout_seconds=300,
        cloud_allowed=False,
        confidence_score=0.95,
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_engagement_policy_low_confidence(sample_roe_file):
    """Create a low-confidence EngagementPolicy."""
    return EngagementPolicy(
        policy_id=uuid4(),
        engagement_id=uuid4(),
        roe_id=sample_roe_file.roe_id,
        scope_cidrs=["192.168.0.0/16"],
        scope_domains=["example.com"],
        scope_urls=[],
        excluded_ips=[],
        restricted_actions=["MODIFY_DATA"],
        max_iterations=10,
        max_retries=5,
        timeout_seconds=600,
        cloud_allowed=True,
        confidence_score=0.62,  # Below 0.85 threshold
        created_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Approval Record Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_approval_record(sample_roe_file):
    """Create a sample ROEApprovalRecord."""
    import hashlib
    
    nonce = "test-nonce-token-12345"
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    
    return ROEApprovalRecord(
        approval_id=uuid4(),
        engagement_id=uuid4(),
        roe_id=sample_roe_file.roe_id,
        approved_by="security-team@example.com",
        approved_at=datetime.now(timezone.utc),
        password_verified=True,
        session_id="session-12345",
        nonce_token_hash=nonce_hash,
    )


@pytest.fixture
def sample_approval_record_unverified(sample_roe_file):
    """Create an approval record without password verification."""
    import hashlib
    
    nonce = "test-nonce-token-67890"
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    
    return ROEApprovalRecord(
        approval_id=uuid4(),
        engagement_id=uuid4(),
        roe_id=sample_roe_file.roe_id,
        approved_by="operator@example.com",
        approved_at=datetime.now(timezone.utc),
        password_verified=False,  # No sudo verification
        session_id="session-67890",
        nonce_token_hash=nonce_hash,
    )


# ---------------------------------------------------------------------------
# Engagement Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_engagement(sample_roe_file):
    """Create a sample Engagement model."""
    now = datetime.now(timezone.utc)
    
    return Engagement(
        engagement_id=uuid4(),
        name="Engagement 2026-04-12",
        operator_id="security-team@example.com",
        scope=EngagementScope(
            scope_cidrs=["192.168.1.0/24"],
            scope_domains=["example.com"],
            scope_urls=[],
        ),
        roe_document_hash=sample_roe_file.content_hash,
        authoriser_identity="security-lead@example.com",
        valid_from=now,
        valid_until=now + timedelta(days=30),
        time_window="09:00-17:00 UTC",
    )


# ---------------------------------------------------------------------------
# Mixed Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def roe_data_set():
    """Provide a complete ROE dataset (file, policy, approval) with consistent IDs."""
    import hashlib
    
    # Generate consistent UUIDs for the dataset
    engagement_id = uuid4()
    roe_id = uuid4()
    
    # ROE File
    roe_yaml = """
scope:
  cidrs:
    - "192.168.1.0/24"
  excludedIps: []
actions:
  - MODIFY_DATA
limits:
  maxIterations: 5
  maxRetries: 3
  timeoutSeconds: 300
  cloudAllowed: false
"""
    content_hash = hashlib.sha256(roe_yaml.encode()).hexdigest()
    
    roe_file = ROEFile(
        roe_id=roe_id,
        filename="test_roe.yaml",
        content_hash=content_hash,
        content_yaml=roe_yaml,
        uploaded_by="test@example.com",
        uploaded_at=datetime.now(timezone.utc),
        version=1,
        is_active=True,
    )
    
    # Engagement Policy
    engagement_policy = EngagementPolicy(
        policy_id=uuid4(),
        engagement_id=engagement_id,
        roe_id=roe_id,
        scope_cidrs=["192.168.1.0/24"],
        scope_domains=[],
        scope_urls=[],
        excluded_ips=[],
        restricted_actions=["MODIFY_DATA"],
        max_iterations=5,
        max_retries=3,
        timeout_seconds=300,
        cloud_allowed=False,
        confidence_score=0.95,
        created_at=datetime.now(timezone.utc),
    )
    
    # Approval Record
    nonce = "test-nonce-token-dataset"
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    
    approval_record = ROEApprovalRecord(
        approval_id=uuid4(),
        engagement_id=engagement_id,
        roe_id=roe_id,
        approved_by="test@example.com",
        approved_at=datetime.now(timezone.utc),
        password_verified=True,
        session_id="session-dataset",
        nonce_token_hash=nonce_hash,
    )
    
    return {
        "roe_file": roe_file,
        "engagement_policy": engagement_policy,
        "approval_record": approval_record,
    }
