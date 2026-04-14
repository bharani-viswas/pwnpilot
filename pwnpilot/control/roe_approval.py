"""
ROE Approval Workflow — user approval flow with sudo verification for engagement launch.

Ticket lifecycle: PENDING → APPROVED | DENIED | EXPIRED

This module handles:
1. Displaying interpreted ROE policies to user (formatted CLI output)
2. Requesting approval via CLI prompt (yes/no)
3. Verifying approval via OS-level sudo authentication (PAM)
4. Session management with 15-minute timeout
5. Nonce token generation for security
6. Audit logging with immutable records

Security model:
- No plain-text passwords stored in memory
- Sudo verification via PAM (OS-level)
- Failed sudo attempts logged
- Session tokens tied to user + timestamp
- Automatic timeout after 15 minutes
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

import structlog

from pwnpilot.agent.roe_interpreter import ExtractedPolicy, InterpretationResult
from pwnpilot.data.models import AuditEvent, OperatorDecision, OperatorDecisionType

log = structlog.get_logger(__name__)

DEFAULT_SESSION_TTL_SECONDS: int = 900  # 15 minutes
DEFAULT_NONCE_LENGTH: int = 32


class SessionExpiredError(Exception):
    pass


class ApprovalDeniedError(Exception):
    pass


class SudoVerificationError(Exception):
    pass


class ApprovalSession:
    """Represents a user approval session with timeout and token security."""

    def __init__(
        self,
        user: str,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        engagement_id: Optional[UUID] = None,
    ):
        self.session_id = str(uuid4())
        self.user = user
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = self.created_at + timedelta(seconds=ttl_seconds)
        self.engagement_id = engagement_id or uuid4()
        
        # Generate secure nonce token
        self._nonce = secrets.token_hex(DEFAULT_NONCE_LENGTH)
        self.is_valid = True
        self.approval_status: Optional[str] = None  # "approved", "denied", "expired"
        self.password_verified = False
        self.verification_timestamp: Optional[datetime] = None

    @property
    def nonce_token(self) -> str:
        """Return the session's secure nonce token."""
        return self._nonce

    def is_expired(self) -> bool:
        """Check if session has expired (15-minute timeout)."""
        now = datetime.now(timezone.utc)
        expired = now > self.expires_at
        if expired and self.is_valid:
            self.is_valid = False
            self.approval_status = "expired"
        return expired

    def to_dict(self) -> dict:
        """Convert session to dict for audit logging."""
        return {
            "session_id": self.session_id,
            "user": self.user,
            "engagement_id": str(self.engagement_id),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_expired": self.is_expired(),
            "approval_status": self.approval_status,
            "password_verified": self.password_verified,
        }


class ApprovalWorkflow:
    """
    Manages user approval workflow for ROE-derived policies.

    Workflow:
    1. Create approval session
    2. Display extracted policies to user
    3. Request approval (yes/no CLI prompt)
    4. Verify sudo password (OS-level PAM auth)
    5. Create ApprovalRecord with audit trail
    """

    def __init__(
        self,
        audit_fn=None,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        decision_store=None,
    ):
        """
        Initialize approval workflow.

        Args:
            audit_fn: Callback function for audit logging (takes AuditEvent)
            session_ttl_seconds: Session timeout in seconds (default 900 = 15 min)
            decision_store: Optional OperatorDecisionStore for persisting v2 decisions
        """
        self._audit_fn = audit_fn
        self._session_ttl = session_ttl_seconds
        self._sessions: dict[str, ApprovalSession] = {}
        self._decision_store = decision_store
        self._logger = logging.getLogger("pwnpilot.approval")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(
        self,
        user: str,
        engagement_id: Optional[UUID] = None,
    ) -> ApprovalSession:
        """Create a new approval session for the given user."""
        session = ApprovalSession(
            user=user,
            ttl_seconds=self._session_ttl,
            engagement_id=engagement_id,
        )
        self._sessions[session.session_id] = session

        log.info(
            "approval.session_created",
            session_id=session.session_id,
            user=user,
            engagement_id=str(engagement_id),
            expires_at=session.expires_at.isoformat(),
        )

        self._audit(
            engagement_id=engagement_id,
            event_type="roe.approval.session_created",
            actor=user,
            payload={
                "session_id": session.session_id,
                "nonce_token": "***",  # Don't log actual token
            },
        )

        return session

    def get_session(self, session_id: str) -> ApprovalSession:
        """Retrieve a session by ID."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        if session.is_expired():
            raise SessionExpiredError(f"Session {session_id} has expired")
        return session

    def display_policies(
        self,
        session_id: str,
        interpretation_result: InterpretationResult,
    ) -> None:
        """Display extracted policies to user in CLI-friendly format."""
        session = self.get_session(session_id)
        policy = interpretation_result.extracted_policy

        print("\n" + "=" * 70)
        print("ROE APPROVAL WORKFLOW — Extracted Policies")
        print("=" * 70)
        print(f"\nSession ID:     {session.session_id}")
        print(f"User:           {session.user}")
        print(f"Expires at:     {session.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"\n{'-' * 70}")

        # Display scope
        print("\n📍 SCOPE (Targets allowed by this engagement):")
        if policy.scope_cidrs:
            print(f"  CIDR blocks: {', '.join(policy.scope_cidrs)}")
        if policy.scope_domains:
            print(f"  Domains: {', '.join(policy.scope_domains)}")
        if policy.scope_urls:
            print(f"  URLs: {', '.join(policy.scope_urls)}")

        # Display exclusions
        if policy.excluded_ips:
            print(f"\n🚫 EXCLUDED IPs (Do NOT target):")
            print(f"  {', '.join(policy.excluded_ips)}")

        # Display actions
        print(f"\n⚔️  ALLOWED ACTIONS:")
        if policy.restricted_actions:
            for action in sorted(policy.restricted_actions):
                print(f"  • {action}")
        else:
            print("  (no actions restricted)")

        # Display limits
        print(f"\n⏱️  EXECUTION LIMITS:")
        print(f"  Max iterations: {policy.max_iterations}")
        print(f"  Max retries: {policy.max_retries}")
        print(f"  Cloud allowed: {policy.cloud_allowed}")

        # Display confidence and warnings
        print(f"\n📊 CONFIDENCE ANALYSIS:")
        print(f"  Confidence score: {interpretation_result.confidence_score:.1%}")
        print(f"  Injection detected: {interpretation_result.injection_detected}")

        if interpretation_result.warnings:
            print(f"\n⚠️  WARNINGS:")
            for warning in interpretation_result.warnings:
                print(f"  • {warning}")

        if interpretation_result.concerns:
            print(f"\n🔴 CONCERNS:")
            for concern in interpretation_result.concerns:
                print(f"  • {concern}")

        if interpretation_result.hallucination_risks:
            print(f"\n🤖 HALLUCINATION RISKS:")
            for risk in interpretation_result.hallucination_risks:
                print(f"  • {risk}")

        print("\n" + "=" * 70 + "\n")

        # Log display event to audit
        self._audit(
            engagement_id=session.engagement_id,
            event_type="roe.approval.policies_displayed",
            actor=session.user,
            payload={
                "session_id": session.session_id,
                "confidence_score": interpretation_result.confidence_score,
                "has_warnings": len(interpretation_result.warnings) > 0,
                "has_concerns": len(interpretation_result.concerns) > 0,
            },
        )

    def request_approval(
        self,
        session_id: str,
    ) -> bool:
        """
        Request approval from user via CLI prompt (yes/no).

        Returns:
            bool: True if user approved, False if denied
        """
        session = self.get_session(session_id)

        prompt = "Do you approve these policies and wish to proceed? (yes/no): "
        while True:
            response = input(prompt).strip().lower()
            if response in ("yes", "y"):
                session.approval_status = "approved"
                log.info(
                    "approval.user_approved",
                    session_id=session.session_id,
                    user=session.user,
                )
                self._audit(
                    engagement_id=session.engagement_id,
                    event_type="roe.approval.user_approved",
                    actor=session.user,
                    payload={"session_id": session.session_id},
                )
                return True
            elif response in ("no", "n"):
                session.approval_status = "denied"
                log.warning(
                    "approval.user_denied",
                    session_id=session.session_id,
                    user=session.user,
                )
                self._audit(
                    engagement_id=session.engagement_id,
                    event_type="roe.approval.user_denied",
                    actor=session.user,
                    payload={"session_id": session.session_id},
                )
                raise ApprovalDeniedError("User denied approval")
            else:
                print("Please enter 'yes' or 'no'")

    def verify_sudo_password(
        self,
        session_id: str,
        password: str,
    ) -> bool:
        """
        Verify sudo password via OS-level PAM authentication.

        This method attempts to verify the sudo password by running a safe
        verification command. The password is NOT stored.

        Args:
            session_id: Session ID for this approval
            password: User's sudo password (not stored)

        Returns:
            bool: True if password verified successfully

        Raises:
            SudoVerificationError: If verification fails or times out
            SessionExpiredError: If session has expired
        """
        session = self.get_session(session_id)

        try:
            # Use 'sudo -S -v' to verify password without executing anything
            # This does NOT run a command, just tests sudo authentication
            result = subprocess.run(
                ["sudo", "-S", "-v"],
                input=password.encode(),
                capture_output=True,
                timeout=5,  # 5 second timeout
            )

            if result.returncode == 0:
                session.password_verified = True
                session.verification_timestamp = datetime.now(timezone.utc)
                
                log.info(
                    "approval.sudo_verified",
                    session_id=session.session_id,
                    user=session.user,
                )
                
                self._audit(
                    engagement_id=session.engagement_id,
                    event_type="roe.approval.sudo_verified",
                    actor=session.user,
                    payload={
                        "session_id": session.session_id,
                        "verification_timestamp": session.verification_timestamp.isoformat(),
                    },
                )
                return True
            else:
                log.warning(
                    "approval.sudo_verification_failed",
                    session_id=session.session_id,
                    user=session.user,
                    stderr=result.stderr.decode()[:100],  # Log first 100 chars
                )
                
                self._audit(
                    engagement_id=session.engagement_id,
                    event_type="roe.approval.sudo_verification_failed",
                    actor=session.user,
                    payload={"session_id": session.session_id},
                )
                
                raise SudoVerificationError("Sudo password verification failed")

        except subprocess.TimeoutExpired:
            log.error(
                "approval.sudo_timeout",
                session_id=session.session_id,
                user=session.user,
            )
            
            self._audit(
                engagement_id=session.engagement_id,
                event_type="roe.approval.sudo_timeout",
                actor=session.user,
                payload={"session_id": session.session_id},
            )
            
            raise SudoVerificationError("Sudo verification timed out (>5s)")
        except subprocess.CalledProcessError as e:
            log.error(
                "approval.sudo_error",
                session_id=session.session_id,
                user=session.user,
                error=str(e),
            )
            
            self._audit(
                engagement_id=session.engagement_id,
                event_type="roe.approval.sudo_error",
                actor=session.user,
                payload={"session_id": session.session_id, "error": str(e)},
            )
            
            raise SudoVerificationError(f"Sudo verification error: {str(e)}")
        except FileNotFoundError:
            log.error("approval.sudo_not_found", user=session.user)
            raise SudoVerificationError("sudo command not found")

    def approve_policies(
        self,
        session_id: str,
        interpretation_result: InterpretationResult,
        password: str,
    ) -> ApprovalRecord:
        """
        Complete approval workflow: verify password, create approval record.

        Args:
            session_id: Session ID for this approval
            interpretation_result: The extracted ROE policies from ROEInterpreter
            password: User's sudo password (for verification)

        Returns:
            ApprovalRecord: The created approval record with all metadata

        Raises:
            SessionExpiredError: If session has expired
            SudoVerificationError: If password verification fails
        """
        session = self.get_session(session_id)

        # Verify sudo password
        self.verify_sudo_password(session_id, password)

        # Create approval record
        record = ApprovalRecord(
            approval_id=uuid4(),
            session_id=session.session_id,
            engagement_id=session.engagement_id,
            user=session.user,
            extracted_policy=interpretation_result.extracted_policy,
            confidence_score=interpretation_result.confidence_score,
            password_verified=session.password_verified,
            approved_at=datetime.now(timezone.utc),
        )

        log.info(
            "approval.policies_approved",
            approval_id=str(record.approval_id),
            session_id=session.session_id,
            engagement_id=str(session.engagement_id),
            user=session.user,
        )

        self._audit(
            engagement_id=session.engagement_id,
            event_type="roe.approval.policies_approved",
            actor=session.user,
            payload={
                "approval_id": str(record.approval_id),
                "session_id": session.session_id,
                "confidence_score": interpretation_result.confidence_score,
            },
        )

        # Emit unified v2 OperatorDecision record
        if self._decision_store is not None:
            try:
                roe_id = record.approval_id
                decision = OperatorDecision(
                    engagement_id=session.engagement_id,
                    decision_type=OperatorDecisionType.ROE_APPROVAL,
                    scope=f"roe:{roe_id}",
                    rationale=(
                        f"ROE policies approved by {session.user} via sudo verification "
                        f"(confidence={interpretation_result.confidence_score:.2f})"
                    ),
                    actor=session.user,
                    roe_id=roe_id,
                    downstream_effect={
                        "session_id": session.session_id,
                        "confidence_score": interpretation_result.confidence_score,
                        "password_verified": session.password_verified,
                        "constraint_count": len(
                            interpretation_result.extracted_policy.constraints
                            if hasattr(interpretation_result.extracted_policy, "constraints")
                            else []
                        ),
                    },
                )
                self._decision_store.record(decision)
            except Exception as exc:
                log.error("roe_approval.decision_record_failed", error=str(exc))

        return record

    def cleanup_sessions(self) -> None:
        """Expire any stale sessions."""
        now = datetime.now(timezone.utc)
        expired = [
            sid
            for sid, session in self._sessions.items()
            if session.is_expired()
        ]

        for sid in expired:
            log.warning("approval.session_cleanup", session_id=sid)
            self._sessions[sid].approval_status = "expired"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _audit(
        self,
        engagement_id: Optional[UUID],
        event_type: str,
        actor: str,
        payload: dict,
    ) -> None:
        """Log an audit event."""
        if self._audit_fn is None:
            return

        audit_event = AuditEvent(
            engagement_id=engagement_id or uuid4(),
            actor=actor,
            event_type=event_type,
            payload=payload,
        )

        try:
            self._audit_fn(audit_event)
        except Exception as e:
            log.error("approval.audit_failed", error=str(e), event_type=event_type)


class ApprovalRecord:
    """
    Represents a completed approval for ROE-derived policies.

    This record is created after user approval and sudo verification,
    and is used to derive the engagement's policy constraints.
    """

    def __init__(
        self,
        approval_id: UUID,
        session_id: str,
        engagement_id: UUID,
        user: str,
        extracted_policy: ExtractedPolicy,
        confidence_score: float,
        password_verified: bool,
        approved_at: datetime,
    ):
        self.approval_id = approval_id
        self.session_id = session_id
        self.engagement_id = engagement_id
        self.user = user
        self.extracted_policy = extracted_policy
        self.confidence_score = confidence_score
        self.password_verified = password_verified
        self.approved_at = approved_at

    def to_dict(self) -> dict:
        """Convert to dict for serialization/logging."""
        return {
            "approval_id": str(self.approval_id),
            "session_id": self.session_id,
            "engagement_id": str(self.engagement_id),
            "user": self.user,
            "extracted_policy": self.extracted_policy.to_dict(),
            "confidence_score": self.confidence_score,
            "password_verified": self.password_verified,
            "approved_at": self.approved_at.isoformat(),
        }
