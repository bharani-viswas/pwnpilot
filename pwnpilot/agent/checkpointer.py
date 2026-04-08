"""
SQLite-backed LangGraph checkpointer.

Extends InMemorySaver with SQLite persistence: every checkpoint write is
also stored in three SQLite tables (lg_checkpoints, lg_checkpoint_blobs,
lg_checkpoint_writes).  On construction the saver re-hydrates its in-memory
maps from the database, so a process restart with the same database file picks
up exactly where it left off.

Usage::

    from pwnpilot.agent.checkpointer import SqliteCheckpointer

    with SqliteCheckpointer.from_path(Path("pwnpilot.db")) as cp:
        graph = build_graph(...).compile(checkpointer=cp)   # pass checkpointer here
        config = {"configurable": {"thread_id": str(engagement_id)}}
        final_state = graph.invoke(initial_state, config=config)

    # Later, to resume:
    with SqliteCheckpointer.from_path(Path("pwnpilot.db")) as cp:
        last = cp.get_tuple(config)          # returns CheckpointTuple or None
        final_state = graph.invoke(None, config=config)   # LangGraph resumes from last cp
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Iterator, Sequence

import structlog
from langgraph.checkpoint.base import (
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_metadata,
)
from langgraph.checkpoint.memory import InMemorySaver
from langchain_core.runnables import RunnableConfig

log = structlog.get_logger(__name__)

# DDL — kept minimal to avoid schema conflicts with rest of the ORM schema
_DDL = """
CREATE TABLE IF NOT EXISTS lg_checkpoints (
    thread_id        TEXT    NOT NULL,
    checkpoint_ns    TEXT    NOT NULL DEFAULT '',
    checkpoint_id    TEXT    NOT NULL,
    parent_id        TEXT,
    checkpoint_data  BLOB    NOT NULL,
    metadata_data    BLOB    NOT NULL,
    PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS lg_checkpoint_blobs (
    thread_id      TEXT    NOT NULL,
    checkpoint_ns  TEXT    NOT NULL DEFAULT '',
    channel        TEXT    NOT NULL,
    version        TEXT    NOT NULL,
    type_str       TEXT    NOT NULL,
    data           BLOB    NOT NULL,
    PRIMARY KEY (thread_id, checkpoint_ns, channel, version)
);

CREATE TABLE IF NOT EXISTS lg_checkpoint_writes (
    thread_id      TEXT    NOT NULL,
    checkpoint_ns  TEXT    NOT NULL DEFAULT '',
    checkpoint_id  TEXT    NOT NULL,
    task_id        TEXT    NOT NULL,
    write_idx      INTEGER NOT NULL,
    channel        TEXT    NOT NULL,
    value_data     BLOB    NOT NULL,
    task_path      TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, write_idx)
);
"""


class SqliteCheckpointer(InMemorySaver, AbstractContextManager):
    """
    In-memory LangGraph checkpointer that also persists every write to SQLite.

    All operations follow InMemorySaver semantics; this class merely adds a
    SQLite side-channel so the state survives process restarts.
    """

    def __init__(self, db_path: Path | str) -> None:
        super().__init__()
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()
        self._reload_from_db()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> SqliteCheckpointer:
        return self

    def __exit__(self, *_: Any) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, db_path: Path | str) -> SqliteCheckpointer:
        """Create and return a SqliteCheckpointer wired to *db_path*."""
        return cls(db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                isolation_level=None,  # auto-commit
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _init_db(self) -> None:
        conn = self._connection()
        conn.executescript(_DDL)

    def _reload_from_db(self) -> None:
        """Reload all persisted checkpoints into the in-memory dictionaries."""
        conn = self._connection()

        # Reload blobs
        for row in conn.execute(
            "SELECT thread_id, checkpoint_ns, channel, version, type_str, data "
            "FROM lg_checkpoint_blobs"
        ):
            tid, ns, ch, ver, type_str, data = row
            self.blobs[(tid, ns, ch, ver)] = (type_str, bytes(data))

        # Reload writes
        for row in conn.execute(
            "SELECT thread_id, checkpoint_ns, checkpoint_id, task_id, write_idx, "
            "channel, value_data, task_path "
            "FROM lg_checkpoint_writes"
        ):
            tid, ns, cid, task_id, widx, ch, val, tpath = row
            key = (tid, ns, cid)
            entry = self.writes.setdefault(key, {})
            entry[(task_id, widx)] = (task_id, ch, self.serde.loads_typed((ch, bytes(val))), tpath)

        # Reload checkpoints
        for row in conn.execute(
            "SELECT thread_id, checkpoint_ns, checkpoint_id, parent_id, "
            "checkpoint_data, metadata_data "
            "FROM lg_checkpoints"
        ):
            tid, ns, cid, parent_id, cp_data, meta_data = row
            self.storage[tid][ns][cid] = (
                ("json", bytes(cp_data)),
                ("json", bytes(meta_data)),
                parent_id,
            )

        log.info(
            "checkpointer.reloaded",
            threads=len(self.storage),
            blobs=len(self.blobs),
        )

    # ------------------------------------------------------------------
    # Overrides — persist to SQLite in addition to in-memory
    # ------------------------------------------------------------------

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        """Save checkpoint to memory AND SQLite."""
        # Let parent handle in-memory state + serialisation
        new_config = super().put(config, checkpoint, metadata, new_versions)

        thread_id: str = config["configurable"]["thread_id"]
        checkpoint_ns: str = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id: str = checkpoint["id"]
        parent_id: str | None = config["configurable"].get("checkpoint_id")

        # Retrieve the bytes the parent just serialised
        stored = self.storage[thread_id][checkpoint_ns].get(checkpoint_id)
        if stored is None:
            return new_config

        cp_type, cp_data = stored[0]   # ('json', bytes)
        meta_type, meta_data = stored[1]

        with self._lock:
            conn = self._connection()
            conn.execute(
                """INSERT OR REPLACE INTO lg_checkpoints
                   (thread_id, checkpoint_ns, checkpoint_id, parent_id,
                    checkpoint_data, metadata_data)
                   VALUES (?,?,?,?,?,?)""",
                (thread_id, checkpoint_ns, checkpoint_id, parent_id,
                 cp_data, meta_data),
            )
            # Persist new blobs
            for ch, ver in new_versions.items():
                blob_key = (thread_id, checkpoint_ns, ch, ver)
                if blob_key in self.blobs:
                    type_str, data = self.blobs[blob_key]
                    conn.execute(
                        """INSERT OR REPLACE INTO lg_checkpoint_blobs
                           (thread_id, checkpoint_ns, channel, version, type_str, data)
                           VALUES (?,?,?,?,?,?)""",
                        (thread_id, checkpoint_ns, ch, str(ver), type_str, data),
                    )

        log.debug(
            "checkpointer.put",
            thread_id=thread_id,
            checkpoint_id=checkpoint_id,
        )
        return new_config

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        """Save writes to memory AND SQLite."""
        super().put_writes(config, writes, task_id, task_path)

        thread_id: str = config["configurable"]["thread_id"]
        checkpoint_ns: str = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id: str | None = config["configurable"].get("checkpoint_id")
        if not checkpoint_id:
            return

        with self._lock:
            conn = self._connection()
            for idx, (channel, value) in enumerate(writes):
                type_str, val_data = self.serde.dumps_typed(value)
                conn.execute(
                    """INSERT OR REPLACE INTO lg_checkpoint_writes
                       (thread_id, checkpoint_ns, checkpoint_id,
                        task_id, write_idx, channel, value_data, task_path)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (thread_id, checkpoint_ns, checkpoint_id,
                     task_id, idx, channel, val_data, task_path),
                )

    def delete_thread(self, thread_id: str) -> None:
        """Delete all checkpoints for a thread from memory AND SQLite."""
        super().delete_thread(thread_id)
        with self._lock:
            conn = self._connection()
            conn.execute(
                "DELETE FROM lg_checkpoints WHERE thread_id=?", (thread_id,)
            )
            conn.execute(
                "DELETE FROM lg_checkpoint_blobs WHERE thread_id=?", (thread_id,)
            )
            conn.execute(
                "DELETE FROM lg_checkpoint_writes WHERE thread_id=?", (thread_id,)
            )
        log.info("checkpointer.thread_deleted", thread_id=thread_id)
