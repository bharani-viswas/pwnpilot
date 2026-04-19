"""
Canonical Pydantic v2 data models for the pwnpilot framework.

schema_version "v2" — breaking cutover, no backward compatibility.

v2 additions:
  - ExecutionEventType / ExecutionEvent: canonical live execution events.
  - OperatorDecisionType / OperatorDecision: unified approval decision model.
  - OperatorDirective: typed operator directive contract.
  - ReplaySnapshot: replay-ready run snapshot.
  - ToolOutputChunk: live stdout/stderr stream chunk.
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


# ---------------------------------------------------------------------------
# v2 execution event types
# ---------------------------------------------------------------------------


class ExecutionEventType(str, Enum):
    # Runner lifecycle
    ACTION_STARTED = "action.started"
    TOOL_OUTPUT_CHUNK = "tool.output_chunk"
    ACTION_COMPLETED = "action.completed"
    ACTION_FAILED = "action.failed"

    # Executor lifecycle
    EXECUTOR_POLICY_CHECKED = "executor.policy_checked"
    EXECUTOR_RECOVERY_HINT = "executor.recovery_hint"

    # Operator control
    OPERATOR_DIRECTIVE_SUBMITTED = "operator.directive_submitted"
    OPERATOR_MODE_CHANGED = "operator.mode_changed"
    OPERATOR_MESSAGE_SENT = "operator.message_sent"

    # Approval events
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"

    # Report / finalization
    REPORT_FINALIZATION_STARTED = "report.finalization_started"
    REPORT_FINALIZATION_FAILED = "report.finalization_failed"
    REPORT_FINALIZED = "report.finalized"

    # Replay / export
    REPLAY_SNAPSHOT_GENERATED = "replay.snapshot_generated"
    ENGAGEMENT_EXPORT_GENERATED = "engagement.export_generated"

    # Memory / repetition
    REPETITION_DETECTED = "repetition.detected"
    VALIDATOR_REJECTED = "validator.rejected"
    FINDING_PERSISTED = "finding.persisted"
    RETRIEVAL_CONTEXT_REFRESHED = "retrieval.context_refreshed"


# ---------------------------------------------------------------------------
# Operator decision types (unified)
# ---------------------------------------------------------------------------


class OperatorDecisionType(str, Enum):
    APPROVE = "approve"
    DENY = "deny"
    DEFER = "defer"
    ESCALATE = "escalate"
    POLICY_EXCEPTION = "policy_exception"
    ROE_APPROVAL = "roe_approval"


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


class OutcomeStatus(str, Enum):
    SUCCESS = "success"
    DEGRADED = "degraded"
    FAILED = "failed"


class FailureReason(str, Enum):
    TARGET_UNREACHABLE = "TargetUnreachable"
    TOOL_MODE_MISMATCH = "ToolModeMismatch"
    AUTH_FAILURE = "AuthFailure"
    TIMEOUT = "Timeout"
    PARSER_DEGRADED = "ParserDegraded"
    NO_ACTIONABLE_OUTPUT = "NoActionableOutput"
    UNKNOWN_RUNTIME_FAILURE = "UnknownRuntimeFailure"


class ToolExecutionResult(BaseModel):
    action_id: UUID
    tool_name: str
    exit_code: int
    duration_ms: int
    stdout_hash: str
    stderr_hash: str
    stdout_evidence_id: UUID | None = None
    stderr_evidence_id: UUID | None = None
    stdout_evidence_path: str | None = None
    stderr_evidence_path: str | None = None
    parsed_output: dict[str, Any] = Field(default_factory=dict)
    parser_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    error_class: ErrorClass | None = None
    outcome_status: OutcomeStatus = OutcomeStatus.SUCCESS
    failure_reasons: list[FailureReason] = Field(default_factory=list)
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
    strategy_step_id: str | None = None
    attack_technique_ids: list[str] = Field(default_factory=list)
    retrieval_sources: list[str] = Field(default_factory=list)
    retrieval_confidence: float | None = None
    specialist_profile: str | None = None
    policy_prior_score: float | None = None
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
    rejection_reason_code: str | None = None
    rejection_reason_detail: str | None = None
    rejection_class: str | None = None
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


# ---------------------------------------------------------------------------
# v2 ExecutionEvent — canonical live execution event
# ---------------------------------------------------------------------------


class ExecutionEvent(BaseModel):
    """
    Canonical v2 execution event.

    Emitted by ToolRunner and ExecutorNode; consumed by the event bus,
    audit store, TUI, CLI live-output, replay, and export paths.
    """
    event_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    action_id: UUID | None = None
    event_type: ExecutionEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str | None = None
    command: str | None = None
    actor: str = "system"
    payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "v2"


# ---------------------------------------------------------------------------
# v2 ToolOutputChunk — live stdout/stderr stream segment
# ---------------------------------------------------------------------------


class ToolOutputChunk(BaseModel):
    """
    A single chunk of live stdout/stderr output from a running tool.
    Buffered per-action with truncation policy (see ToolOutputStream).
    """
    chunk_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    engagement_id: UUID
    stream: str  # "stdout" | "stderr"
    data: str    # UTF-8 decoded chunk (with replacement for invalid bytes)
    sequence: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    truncated: bool = False
    schema_version: str = "v2"


# ---------------------------------------------------------------------------
# v2 OperatorDirective — typed operator intent contract
# ---------------------------------------------------------------------------


class OperatorDirective(BaseModel):
    """
    Typed operator directive consumed by planner and validator.
    Every field is optional; only supplied fields alter behavior.
    """
    directive_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    operator_id: str

    # Intent fields consumed by planner
    objective: str | None = None
    requested_focus: str | None = None
    constraints: list[str] = Field(default_factory=list)
    paused_tool_families: list[str] = Field(default_factory=list)
    notes: str | None = None

    schema_version: str = "v2"


# ---------------------------------------------------------------------------
# v2 OperatorDecision — unified approval/denial/deferral model
# ---------------------------------------------------------------------------


class OperatorDecision(BaseModel):
    """
    Unified operator decision model for runtime approvals, ROE approvals,
    policy exceptions, and deferred decisions.

    Replaces the parallel ApprovalTicket and ROEApprovalRecord models
    for all operator-facing decision flows.
    """
    decision_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    decision_type: OperatorDecisionType
    scope: str  # e.g. "action:<action_id>", "roe:<roe_id>", "tool_family:<name>"
    rationale: str
    actor: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expiry: datetime | None = None
    downstream_effect: dict[str, Any] = Field(default_factory=dict)
    action_id: UUID | None = None     # link to specific action if applicable
    roe_id: UUID | None = None        # link to ROE if applicable
    ticket_id: UUID | None = None     # link to originating approval ticket if applicable
    schema_version: str = "v2"

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# v2 ReplaySnapshot — replay-ready run state
# ---------------------------------------------------------------------------


class ReplaySnapshot(BaseModel):
    """
    Snapshot of a completed or in-progress engagement for replay/export.
    Sourced from audit events, evidence, metrics, and approval decisions.
    """
    snapshot_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Timeline of all ExecutionEvents in sequence order
    event_timeline: list[dict[str, Any]] = Field(default_factory=list)
    # All operator decisions
    operator_decisions: list[dict[str, Any]] = Field(default_factory=list)
    # Planner rejection summary
    planner_rejections: list[dict[str, Any]] = Field(default_factory=list)
    # Run-level metadata (verdict, health, finalization status)
    run_metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "v2"
