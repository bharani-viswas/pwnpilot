from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.engagement_name_store import EngagementNameStore


def _session():
    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    session = Session()
    return session


def test_bind_and_resolve_name() -> None:
    session = _session()
    store = EngagementNameStore(session)
    eid = uuid4()

    key = store.bind("Acme External Q2", eid)
    assert key == "acme-external-q2"

    resolved = store.resolve("Acme External Q2")
    assert resolved == eid


def test_resolve_accepts_uuid_reference() -> None:
    session = _session()
    store = EngagementNameStore(session)
    eid = uuid4()

    assert store.resolve(str(eid)) == eid


def test_bind_updates_existing_name() -> None:
    session = _session()
    store = EngagementNameStore(session)

    first = uuid4()
    second = uuid4()

    store.bind("Client Red Team", first)
    store.bind("Client Red Team", second)

    assert store.resolve("client red team") == second
