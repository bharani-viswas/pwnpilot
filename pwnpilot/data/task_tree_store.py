"""
TaskTreeStore — persistent strategic task tree memory (Phase 6B).

Provides deterministic task tree operations for long-horizon engagements:
- create_node
- advance_node
- invalidate_node
- list_open_nodes
- summarize_for_planner
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Session


class _Base(DeclarativeBase):
    pass


class TaskTreeNodeRow(_Base):
    __tablename__ = "task_tree_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(String(36), nullable=False, unique=True, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    objective_id = Column(String(128), nullable=False, index=True)
    parent_id = Column(String(36), nullable=True)
    tactic = Column(String(128), nullable=False, default="")
    target_asset = Column(Text, nullable=False, default="")
    current_hypothesis = Column(Text, nullable=False, default="")
    node_state = Column(String(32), nullable=False, default="open")
    confidence = Column(Float, nullable=False, default=0.5)
    supporting_evidence_ids = Column(Text, nullable=False, default="[]")
    invalidation_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    schema_version = Column(String(16), nullable=False, default="v1")


class TaskTreeStore:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        _Base.metadata.create_all(bind=session.get_bind())

    def create_node(
        self,
        engagement_id: UUID,
        objective_id: str,
        tactic: str,
        target_asset: str,
        current_hypothesis: str,
        confidence: float = 0.5,
        parent_id: str | None = None,
        supporting_evidence_ids: list[str] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        node_id = str(uuid4())
        row = TaskTreeNodeRow(
            node_id=node_id,
            engagement_id=str(engagement_id),
            objective_id=str(objective_id or "").strip() or "objective-unknown",
            parent_id=str(parent_id).strip() if parent_id else None,
            tactic=str(tactic or "").strip(),
            target_asset=str(target_asset or "").strip(),
            current_hypothesis=str(current_hypothesis or "").strip(),
            node_state="open",
            confidence=max(0.0, min(1.0, float(confidence))),
            supporting_evidence_ids=json.dumps(supporting_evidence_ids or []),
            created_at=now,
            updated_at=now,
            schema_version="v1",
        )
        with self._lock:
            self._session.add(row)
            self._session.commit()
        return node_id

    def advance_node(
        self,
        node_id: str,
        new_state: str,
        confidence: float | None = None,
        supporting_evidence_ids: list[str] | None = None,
        current_hypothesis: str | None = None,
    ) -> bool:
        state = str(new_state or "").strip().lower()
        if state not in {"open", "in_progress", "completed", "blocked"}:
            raise ValueError(f"Invalid task node state: {new_state}")
        with self._lock:
            row = self._session.query(TaskTreeNodeRow).filter_by(node_id=node_id).first()
            if row is None:
                return False
            row.node_state = state
            if confidence is not None:
                row.confidence = max(0.0, min(1.0, float(confidence)))
            if supporting_evidence_ids is not None:
                row.supporting_evidence_ids = json.dumps(supporting_evidence_ids)
            if current_hypothesis is not None:
                row.current_hypothesis = str(current_hypothesis)
            row.updated_at = datetime.now(timezone.utc)
            self._session.commit()
        return True

    def invalidate_node(self, node_id: str, reason: str) -> bool:
        with self._lock:
            row = self._session.query(TaskTreeNodeRow).filter_by(node_id=node_id).first()
            if row is None:
                return False
            row.node_state = "invalidated"
            row.invalidation_reason = str(reason or "unknown")
            row.updated_at = datetime.now(timezone.utc)
            self._session.commit()
        return True

    def list_open_nodes(self, engagement_id: UUID, limit: int = 20) -> list[dict[str, Any]]:
        rows = (
            self._session.query(TaskTreeNodeRow)
            .filter(
                TaskTreeNodeRow.engagement_id == str(engagement_id),
                TaskTreeNodeRow.node_state.in_(["open", "in_progress", "blocked"]),
            )
            .order_by(TaskTreeNodeRow.updated_at.desc())
            .limit(max(1, int(limit)))
            .all()
        )
        return [self._row_to_dict(r) for r in rows]

    def summarize_for_planner(self, engagement_id: UUID, limit: int = 8) -> dict[str, Any]:
        nodes = self.list_open_nodes(engagement_id=engagement_id, limit=limit)
        return {
            "open_nodes": nodes,
            "open_count": len([n for n in nodes if n.get("node_state") == "open"]),
            "in_progress_count": len([n for n in nodes if n.get("node_state") == "in_progress"]),
            "blocked_count": len([n for n in nodes if n.get("node_state") == "blocked"]),
        }

    def _row_to_dict(self, row: TaskTreeNodeRow) -> dict[str, Any]:
        try:
            evidence = json.loads(row.supporting_evidence_ids or "[]")
        except json.JSONDecodeError:
            evidence = []
        return {
            "node_id": row.node_id,
            "objective_id": row.objective_id,
            "parent_id": row.parent_id,
            "tactic": row.tactic,
            "target_asset": row.target_asset,
            "current_hypothesis": row.current_hypothesis,
            "node_state": row.node_state,
            "confidence": row.confidence,
            "supporting_evidence_ids": evidence,
            "invalidation_reason": row.invalidation_reason,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
