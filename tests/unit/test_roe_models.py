"""
Unit tests for Phase 4: ROE Database Models.

Tests for ROEFile, EngagementPolicy, and ROEApprovalRecord models with immutability,
serialization, and audit trail integrity.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from pwnpilot.data.models import (
    ROEFile,
    EngagementPolicy,
    ROEApprovalRecord,
    Engagement,
    EngagementScope,
)


class TestROEFileModel:
    """Test ROEFile model (immutable ROE storage)."""

    def test_roe_file_creation(self, sample_roe_file):
        """Test creating a ROEFile instance."""
        assert sample_roe_file.roe_id is not None
        assert sample_roe_file.filename == "engagement_roe_2026_04_12.yaml"
        assert len(sample_roe_file.content_hash) == 64  # SHA256 hex
        assert sample_roe_file.version == 1
        assert sample_roe_file.is_active is True

    def test_roe_file_immutability(self, sample_roe_file):
        """Test that ROEFile is frozen (immutable)."""
        with pytest.raises(Exception):  # Dataclass frozen
            sample_roe_file.version = 2

    def test_roe_file_schema_version(self, sample_roe_file):
        """Test schema version is present."""
        assert sample_roe_file.schema_version == "v1"

    def test_roe_file_content_hash_consistency(self, sample_roe_yaml_content):
        """Test content hash is consistent."""
        import hashlib
        
        expected_hash = hashlib.sha256(sample_roe_yaml_content.encode()).hexdigest()
        roe = ROEFile(
            roe_id=uuid4(),
            filename="test.yaml",
            content_hash=expected_hash,
            content_yaml=sample_roe_yaml_content,
            uploaded_by="test@example.com",
            uploaded_at=datetime.now(timezone.utc),
        )
        
        # Recalculate hash to verify
        recalculated = hashlib.sha256(roe.content_yaml.encode()).hexdigest()
        assert recalculated == roe.content_hash

    def test_roe_file_multiple_versions(self, sample_roe_file, sample_roe_file_v2):
        """Test storing multiple versions of the same ROE."""
        assert sample_roe_file.version == 1
        assert sample_roe_file_v2.version == 2
        assert sample_roe_file.roe_id != sample_roe_file_v2.roe_id
        assert sample_roe_file.content_hash != sample_roe_file_v2.content_hash

    def test_roe_file_upload_timestamp(self, sample_roe_file):
        """Test upload timestamp is recorded."""
        assert isinstance(sample_roe_file.uploaded_at, datetime)
        assert sample_roe_file.uploaded_at.tzinfo is not None


class TestEngagementPolicyModel:
    """Test EngagementPolicy model (ROE-derived policies)."""

    def test_engagement_policy_creation(self, sample_engagement_policy):
        """Test creating an EngagementPolicy instance."""
        assert sample_engagement_policy.policy_id is not None
        assert sample_engagement_policy.engagement_id is not None
        assert len(sample_engagement_policy.scope_cidrs) > 0
        assert sample_engagement_policy.confidence_score == 0.95

    def test_engagement_policy_immutability(self, sample_engagement_policy):
        """Test that EngagementPolicy is frozen."""
        with pytest.raises(Exception):
            sample_engagement_policy.max_iterations = 10

    def test_engagement_policy_scope_lists(self, sample_engagement_policy):
        """Test scope fields are properly stored as lists."""
        assert isinstance(sample_engagement_policy.scope_cidrs, list)
        assert isinstance(sample_engagement_policy.scope_domains, list)
        assert isinstance(sample_engagement_policy.scope_urls, list)
        assert isinstance(sample_engagement_policy.excluded_ips, list)
        assert isinstance(sample_engagement_policy.restricted_actions, list)

    def test_engagement_policy_confidence_bounds(self):
        """Test confidence score must be between 0.0 and 1.0."""
        engagement_id = uuid4()
        roe_id = uuid4()
        
        # Valid low confidence
        policy_low = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=engagement_id,
            roe_id=roe_id,
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=[],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=5,
            max_retries=3,
            timeout_seconds=300,
            cloud_allowed=False,
            confidence_score=0.0,  # Lowest valid
        )
        assert policy_low.confidence_score == 0.0
        
        # Valid high confidence
        policy_high = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=engagement_id,
            roe_id=roe_id,
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=[],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=5,
            max_retries=3,
            timeout_seconds=300,
            cloud_allowed=False,
            confidence_score=1.0,  # Highest valid
        )
        assert policy_high.confidence_score == 1.0

    def test_engagement_policy_low_confidence_flag(self, sample_engagement_policy_low_confidence):
        """Test low confidence score (below 0.85 threshold)."""
        assert sample_engagement_policy_low_confidence.confidence_score < 0.85
        assert sample_engagement_policy_low_confidence.confidence_score == 0.62

    def test_engagement_policy_creation_timestamp(self, sample_engagement_policy):
        """Test policy creation timestamp is recorded."""
        assert isinstance(sample_engagement_policy.created_at, datetime)
        assert sample_engagement_policy.created_at.tzinfo is not None

    def test_engagement_policy_cloud_allowed_flag(self, sample_engagement_policy):
        """Test cloud_allowed flag controls cloud operations."""
        assert sample_engagement_policy.cloud_allowed is False
        
        policy_with_cloud = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=uuid4(),
            roe_id=uuid4(),
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=[],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=5,
            max_retries=3,
            timeout_seconds=300,
            cloud_allowed=True,  # Cloud operations allowed
            confidence_score=0.95,
        )
        assert policy_with_cloud.cloud_allowed is True


class TestROEApprovalRecordModel:
    """Test ROEApprovalRecord model (immutable approval audit trail)."""

    def test_approval_record_creation(self, sample_approval_record):
        """Test creating an ROEApprovalRecord instance."""
        assert sample_approval_record.approval_id is not None
        assert sample_approval_record.engagement_id is not None
        assert sample_approval_record.roe_id is not None
        assert sample_approval_record.password_verified is True

    def test_approval_record_immutability(self, sample_approval_record):
        """Test that ROEApprovalRecord is frozen."""
        with pytest.raises(Exception):
            sample_approval_record.password_verified = False

    def test_approval_record_password_verification_status(
        self,
        sample_approval_record,
        sample_approval_record_unverified,
    ):
        """Test password verification status is tracked."""
        assert sample_approval_record.password_verified is True
        assert sample_approval_record_unverified.password_verified is False

    def test_approval_record_session_tracking(self, sample_approval_record):
        """Test session ID is recorded for audit trail."""
        assert sample_approval_record.session_id == "session-12345"

    def test_approval_record_nonce_hash(self, sample_approval_record):
        """Test nonce token is hashed (not stored in plain)."""
        # Should be SHA256 hex (64 chars)
        assert len(sample_approval_record.nonce_token_hash) == 64
        # Verify it's hex
        int(sample_approval_record.nonce_token_hash, 16)  # Should not raise

    def test_approval_record_timestamp(self, sample_approval_record):
        """Test approval timestamp is recorded."""
        assert isinstance(sample_approval_record.approved_at, datetime)
        assert sample_approval_record.approved_at.tzinfo is not None

    def test_approval_record_by_field(self, sample_approval_record):
        """Test approved_by field tracks approver identity."""
        assert sample_approval_record.approved_by == "security-team@example.com"


class TestROEModelsIntegration:
    """Integration tests for ROE models working together."""

    def test_roe_data_set_consistency(self, roe_data_set):
        """Test complete ROE dataset (file, policy, approval)."""
        roe_file = roe_data_set["roe_file"]
        policy = roe_data_set["engagement_policy"]
        approval = roe_data_set["approval_record"]
        
        # All reference the same ROE
        assert policy.roe_id == roe_file.roe_id
        assert approval.roe_id == roe_file.roe_id
        
        # Approval references the engagement with policy
        assert approval.engagement_id == policy.engagement_id

    def test_engagement_to_policy_mapping(self):
        """Test mapping between Engagement and EngagementPolicy."""
        engagement_id = uuid4()
        roe_id = uuid4()
        
        # Create engagement with specific scope
        engagement = Engagement(
            engagement_id=engagement_id,
            name="Test Engagement",
            operator_id="operator@example.com",
            scope=EngagementScope(
                scope_cidrs=["10.0.0.0/8"],
                scope_domains=["example.com"],
                scope_urls=[],
            ),
            roe_document_hash="abc123",
            authoriser_identity="lead@example.com",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc) + timedelta(days=30),
        )
        
        # Create policy matching the same scope
        policy = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=engagement_id,
            roe_id=roe_id,
            scope_cidrs=engagement.scope.scope_cidrs,
            scope_domains=engagement.scope.scope_domains,
            scope_urls=engagement.scope.scope_urls,
            excluded_ips=[],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=5,
            max_retries=3,
            timeout_seconds=300,
            cloud_allowed=False,
            confidence_score=0.95,
        )
        
        # Policy should respect engagement scope
        assert policy.scope_cidrs == engagement.scope.scope_cidrs
        assert policy.scope_domains == engagement.scope.scope_domains

    def test_multi_policy_per_engagement(self):
        """Test multiple policies can be associated with an engagement."""
        engagement_id = uuid4()
        roe_id_1 = uuid4()
        roe_id_2 = uuid4()
        
        policy_1 = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=engagement_id,
            roe_id=roe_id_1,
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=[],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=["MODIFY_DATA"],
            max_iterations=5,
            max_retries=3,
            timeout_seconds=300,
            cloud_allowed=False,
            confidence_score=0.95,
        )
        
        policy_2 = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=engagement_id,  # Same engagement, different ROE
            roe_id=roe_id_2,
            scope_cidrs=["192.168.0.0/16"],
            scope_domains=["example.com"],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=["DELETE_DATA"],
            max_iterations=10,
            max_retries=5,
            timeout_seconds=600,
            cloud_allowed=True,
            confidence_score=0.88,
        )
        
        assert policy_1.engagement_id == policy_2.engagement_id
        assert policy_1.roe_id != policy_2.roe_id

    def test_approval_track_across_policies(self):
        """Test approvals can track across multiple ROE updates."""
        engagement_id = uuid4()
        roe_id_v1 = uuid4()
        roe_id_v2 = uuid4()
        
        approval_v1 = ROEApprovalRecord(
            approval_id=uuid4(),
            engagement_id=engagement_id,
            roe_id=roe_id_v1,
            approved_by="operator@example.com",
            approved_at=datetime.now(timezone.utc),
            password_verified=True,
            session_id="session-v1",
            nonce_token_hash="hash-v1",
        )
        
        approval_v2 = ROEApprovalRecord(
            approval_id=uuid4(),
            engagement_id=engagement_id,  # Same engagement
            roe_id=roe_id_v2,  # New ROE version
            approved_by="operator@example.com",
            approved_at=datetime.now(timezone.utc),
            password_verified=True,
            session_id="session-v2",
            nonce_token_hash="hash-v2",
        )
        
        assert approval_v1.engagement_id == approval_v2.engagement_id
        assert approval_v1.roe_id != approval_v2.roe_id


class TestROEModelsEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_roe_file_empty_content(self):
        """Test ROEFile can store empty YAML content."""
        roe = ROEFile(
            roe_id=uuid4(),
            filename="empty.yaml",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty string sha256
            content_yaml="",
            uploaded_by="test@example.com",
            uploaded_at=datetime.now(timezone.utc),
        )
        assert roe.content_yaml == ""

    def test_engagement_policy_empty_scope_lists(self):
        """Test EngagementPolicy with empty scope lists."""
        policy = EngagementPolicy(
            policy_id=uuid4(),
            engagement_id=uuid4(),
            roe_id=uuid4(),
            scope_cidrs=[],
            scope_domains=[],
            scope_urls=[],
            excluded_ips=[],
            restricted_actions=[],
            max_iterations=1,
            max_retries=1,
            timeout_seconds=60,
            cloud_allowed=False,
            confidence_score=0.0,
        )
        
        assert len(policy.scope_cidrs) == 0
        assert len(policy.excluded_ips) == 0

    def test_approval_record_minimal_session_id(self):
        """Test ROEApprovalRecord with minimal session ID."""
        approval = ROEApprovalRecord(
            approval_id=uuid4(),
            engagement_id=uuid4(),
            roe_id=uuid4(),
            approved_by="test@example.com",
            approved_at=datetime.now(timezone.utc),
            password_verified=False,
            session_id="s",  # Minimal
            nonce_token_hash="0" * 64,
        )
        
        assert approval.session_id == "s"

    def test_roe_models_round_trip_serialization(self, sample_roe_file, sample_engagement_policy):
        """Test models can be serialized to dict and back."""
        # ROEFile
        roe_dict = sample_roe_file.model_dump()
        roe_restored = ROEFile(**roe_dict)
        assert roe_restored.roe_id == sample_roe_file.roe_id
        
        # EngagementPolicy
        policy_dict = sample_engagement_policy.model_dump()
        policy_restored = EngagementPolicy(**policy_dict)
        assert policy_restored.policy_id == sample_engagement_policy.policy_id
