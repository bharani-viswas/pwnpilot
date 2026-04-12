"""
Canonical Pydantic v2 data models for the pwnpilot framework.

All models carry schema_version = "v1" for forward-compatibility and migration support.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    RECON_PASSIVE = "recon_passive"
    ACTIVE_SCAN = "active_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    DATA_EXFIL = "data_exfil"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exploitability(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    DEFERRED = "deferred"
    EXPIRED = "expired"


class GateType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"
    RATE_LIMIT = "rate_limit"
    SCOPE_VIOLATION = "scope_violation"


# ---------------------------------------------------------------------------
# ActionRequest
# ---------------------------------------------------------------------------


class ActionRequest(BaseModel):
    action_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    action_type: ActionType
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: list[str] = Field(default_factory=list)
    risk_level: RiskLevel
    requires_approval: bool = False
    schema_version: str = "v1"

    model_config = {"frozen": True}

    def payload_hash(self) -> str:
        raw = self.model_dump_json(exclude={"schema_version"})
        return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# ToolExecutionResult
# ---------------------------------------------------------------------------


class ErrorClass(str, Enum):
    TIMEOUT = "TIMEOUT"
    PARSE_ERROR = "PARSE_ERROR"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    TRUST_ERROR = "TRUST_ERROR"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    NONZERO_EXIT = "NONZERO_EXIT"
    HALTED = "HALTED"


class ToolExecutionResult(BaseModel):
    action_id: UUID
    tool_name: str
    exit_code: int
    duration_ms: int
    stdout_hash: str
    stderr_hash: str
    parsed_output: dict[str, Any] = Field(default_factory=dict)
    parser_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    error_class: ErrorClass | None = None
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    asset_ref: str
    title: str
    vuln_ref: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    exploitability: Exploitability = Exploitability.NONE
    cvss_vector: str | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    remediation: str = ""
    status: FindingStatus = FindingStatus.NEW
    schema_version: str = "v1"

    def fingerprint(self) -> str:
        raw = f"{self.asset_ref}:{self.vuln_ref}:{self.tool_name if hasattr(self, 'tool_name') else ''}"
        return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str = ""
    prev_event_hash: str = ""
    decision_context: dict[str, Any] | None = None
    schema_version: str = "v1"

    @model_validator(mode="after")
    def compute_payload_hash(self) -> "AuditEvent":
        if not self.payload_hash:
            raw = json.dumps(self.payload, sort_keys=True, default=str)
            object.__setattr__(self, "payload_hash", hashlib.sha256(raw.encode()).hexdigest())
        return self


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------


class PolicyDecision(BaseModel):
    verdict: PolicyVerdict
    reason: str
    gate_type: GateType
    action_id: UUID | None = None
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# ApprovalTicket
# ---------------------------------------------------------------------------


class ApprovalTicket(BaseModel):
    ticket_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    engagement_id: UUID
    action_type: ActionType
    tool_name: str
    rationale: str
    impact_preview: str
    risk_level: RiskLevel
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None
    expires_at: datetime | None = None
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# PlannerProposal (inter-agent message via AgentState)
# ---------------------------------------------------------------------------


class PlannerProposal(BaseModel):
    action_type: str
    tool_name: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    estimated_risk: RiskLevel
    rejection_reason: str | None = None
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# ValidationResult (inter-agent message via AgentState)
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    verdict: str  # "approve" | "reject" | "escalate"
    risk_override: RiskLevel | None = None
    rationale: str
    schema_version: str = "v1"

    @field_validator("verdict")
    @classmethod
    def verdict_must_be_valid(cls, v: str) -> str:
        if v not in {"approve", "reject", "escalate"}:
            raise ValueError(f"Invalid verdict: {v}. Must be approve|reject|escalate")
        return v


# ---------------------------------------------------------------------------
# Engagement models
# ---------------------------------------------------------------------------


class EngagementScope(BaseModel):
    scope_cidrs: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_urls: list[str] = Field(default_factory=list)


class Engagement(BaseModel):
    engagement_id: UUID = Field(default_factory=uuid4)
    name: str
    operator_id: str
    scope: EngagementScope
    roe_document_hash: str
    authoriser_identity: str
    valid_from: datetime
    valid_until: datetime
    time_window: str | None = None
    schema_version: str = "v1"

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.valid_from <= now <= self.valid_until


# ---------------------------------------------------------------------------
# Evidence index entry
# ---------------------------------------------------------------------------


class EvidenceIndex(BaseModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    engagement_id: UUID
    file_path: str
    sha256_hash: str
    size_bytes: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    truncated: bool = False
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# ROE models (Phase 4)
# ---------------------------------------------------------------------------


class ROEFile(BaseModel):
    """Represents a stored ROE (Rules of Engagement) file with versioning."""
    
    roe_id: UUID = Field(default_factory=uuid4)
    filename: str
    content_hash: str  # SHA256 of original YAML file
    content_yaml: str  # Full YAML content (immutable)
    uploaded_by: str
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1  # For tracking updates
    is_active: bool = True  # Current ROE version for engagement
    schema_version: str = "v1"
    
    model_config = {"frozen": True}


class EngagementPolicy(BaseModel):
    """Represents policies derived from ROE for a specific engagement."""
    
    policy_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    roe_id: UUID
    scope_cidrs: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_urls: list[str] = Field(default_factory=list)
    excluded_ips: list[str] = Field(default_factory=list)
    restricted_actions: list[str] = Field(default_factory=list)
    max_iterations: int
    max_retries: int
    timeout_seconds: int
    cloud_allowed: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = "v1"
    
    model_config = {"frozen": True}


class ROEApprovalRecord(BaseModel):
    """Immutable record of ROE approval with audit trail."""
    
    approval_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    roe_id: UUID
    approved_by: str
    approved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    password_verified: bool  # Sudo password verification status
    session_id: str  # Reference to ApprovalSession for audit trail
    nonce_token_hash: str  # Hash of nonce (not plain nonce)
    schema_version: str = "v1"
    
    model_config = {"frozen": True}
