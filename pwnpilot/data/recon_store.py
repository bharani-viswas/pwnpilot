"""
Recon Store — persistent graph of hosts, services, ports, domains, and technologies.

Schema: SQLite (WAL mode, lab) / PostgreSQL (production) via SQLAlchemy.
WAL mode: PRAGMA journal_mode=WAL, PRAGMA synchronous=NORMAL (allows concurrent readers).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session

log = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    pass


class HostRow(Base):
    __tablename__ = "recon_hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String(36), nullable=False, unique=True, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255), nullable=True)
    os_guess = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="unknown")
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("engagement_id", "ip_address", name="uq_eng_ip"),
    )


class ServiceRow(Base):
    __tablename__ = "recon_services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String(36), nullable=False, unique=True, index=True)
    host_id = Column(String(36), nullable=False, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False, default="tcp")
    service_name = Column(String(128), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(128), nullable=True)
    banner = Column(Text, nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_host_port_proto"),
    )


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn: Any, _: Any) -> None:
    """Enable WAL mode for SQLite connections (no-op for PostgreSQL)."""
    try:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
    except Exception:
        pass  # Not SQLite; ignore


class ReconStore:
    def __init__(self, session: Session) -> None:
        self._session = session
        Base.metadata.create_all(session.bind)  # type: ignore[arg-type]

    def upsert_host(
        self,
        engagement_id: UUID,
        ip_address: str,
        hostname: str | None = None,
        os_guess: str | None = None,
        status: str = "up",
    ) -> str:
        now = datetime.now(timezone.utc)
        existing = (
            self._session.query(HostRow)
            .filter(
                HostRow.engagement_id == str(engagement_id),
                HostRow.ip_address == ip_address,
            )
            .first()
        )
        if existing:
            existing.hostname = hostname or existing.hostname
            existing.os_guess = os_guess or existing.os_guess
            existing.status = status
            existing.last_seen = now
            self._session.commit()
            return existing.host_id
        else:
            host_id = str(uuid4())
            row = HostRow(
                host_id=host_id,
                engagement_id=str(engagement_id),
                ip_address=ip_address,
                hostname=hostname,
                os_guess=os_guess,
                status=status,
                first_seen=now,
                last_seen=now,
            )
            self._session.add(row)
            self._session.commit()
            log.info("recon.host_added", ip=ip_address, engagement=str(engagement_id))
            return host_id

    def upsert_service(
        self,
        host_id: str,
        engagement_id: UUID,
        port: int,
        protocol: str = "tcp",
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        existing = (
            self._session.query(ServiceRow)
            .filter(
                ServiceRow.host_id == host_id,
                ServiceRow.port == port,
                ServiceRow.protocol == protocol,
            )
            .first()
        )
        if existing:
            existing.service_name = service_name or existing.service_name
            existing.product = product or existing.product
            existing.version = version or existing.version
            existing.banner = banner or existing.banner
            existing.last_seen = now
            self._session.commit()
            return existing.service_id
        else:
            service_id = str(uuid4())
            row = ServiceRow(
                service_id=service_id,
                host_id=host_id,
                engagement_id=str(engagement_id),
                port=port,
                protocol=protocol,
                service_name=service_name,
                product=product,
                version=version,
                banner=banner,
                last_seen=now,
            )
            self._session.add(row)
            self._session.commit()
            log.info(
                "recon.service_added",
                host_id=host_id,
                port=port,
                proto=protocol,
            )
            return service_id

    def hosts_for_engagement(self, engagement_id: UUID) -> list[dict]:
        rows = (
            self._session.query(HostRow)
            .filter(HostRow.engagement_id == str(engagement_id))
            .all()
        )
        return [
            {
                "host_id": r.host_id,
                "ip_address": r.ip_address,
                "hostname": r.hostname,
                "os_guess": r.os_guess,
                "status": r.status,
            }
            for r in rows
        ]

    def services_for_host(self, host_id: str) -> list[dict]:
        rows = (
            self._session.query(ServiceRow)
            .filter(ServiceRow.host_id == host_id)
            .all()
        )
        return [
            {
                "service_id": r.service_id,
                "port": r.port,
                "protocol": r.protocol,
                "service_name": r.service_name,
                "product": r.product,
                "version": r.version,
            }
            for r in rows
        ]

    def services_for_engagement(self, engagement_id: UUID) -> list[dict]:
        """Return all services for every host in the engagement, each entry
        including the parent host's ip_address."""
        from sqlalchemy.orm import Query

        hosts = self.hosts_for_engagement(engagement_id)
        result: list[dict] = []
        for host in hosts:
            for svc in self.services_for_host(host["host_id"]):
                result.append({**svc, "ip": host["ip_address"]})
        return result
