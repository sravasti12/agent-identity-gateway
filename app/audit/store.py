import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from threading import RLock
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

EventType = Literal[
    "human_auth", "agent_auth", "delegation_created", "delegation_accepted", "delegation_rejected",
    "exchange", "opa_decision", "mcp_invocation", "agent_onboarded", "agent_state",
    "rotation", "access_review", "permissions_changed", "provider_revocation",
]
Decision = Literal["allow", "deny", "success", "failure", "pending"]
GENESIS = "0" * 64


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: datetime
    event_type: EventType
    actor: str | None = None
    subject: str | None = None
    agent: str | None = None
    action: str
    resource: str | None = None
    requested_scope: str | None = None
    decision: Decision
    reason_code: str
    correlation_id: str


class AuditRecord(AuditEvent):
    sequence: int
    previous_hash: str
    event_hash: str


class ChainResult(BaseModel):
    valid: bool
    records_checked: int
    failed_sequence: int | None = None


def identifier(value: str | None) -> str | None:
    # Record only opaque identity identifiers, never raw headers or payloads.
    if value is None or re.fullmatch(r"[A-Za-z0-9_:-]{1,160}", value):
        return value
    return "[redacted]"


def digest(sequence: int, previous_hash: str, canonical: str) -> str:
    return hashlib.sha256(f"{sequence}\n{previous_hash}\n{canonical}".encode()).hexdigest()


class Database:
    def __init__(self, path: str) -> None:
        self.connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.lock = RLock()
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY, client_id TEXT UNIQUE NOT NULL, document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY, document TEXT NOT NULL, previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL, event_type TEXT NOT NULL, agent TEXT, decision TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_head (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                sequence INTEGER NOT NULL, event_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_event_filter ON audit_events(event_type, agent, sequence);
        """)
        self.connection.execute("INSERT OR IGNORE INTO audit_head VALUES (1, 0, ?)", (GENESIS,))

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    def audit(
        self, event_type: EventType, action: str, decision: Decision, reason: str, correlation: str,
        *, actor: str | None = None, subject: str | None = None, agent: str | None = None,
        resource: str | None = None, scope: str | None = None, db: sqlite3.Connection | None = None,
    ) -> None:
        event = AuditEvent(
            id=uuid4().hex, timestamp=datetime.now(UTC), event_type=event_type,
            actor=identifier(actor), subject=identifier(subject), agent=identifier(agent),
            action=action, resource=resource, requested_scope=scope, decision=decision,
            reason_code=reason, correlation_id=correlation,
        )
        canonical = json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if db is None:
            with self.transaction() as conn:
                self._append(conn, event, canonical)
        else:
            self._append(db, event, canonical)

    @staticmethod
    def _append(db: sqlite3.Connection, event: AuditEvent, canonical: str) -> None:
        row = db.execute("SELECT sequence, event_hash FROM audit_head WHERE singleton=1").fetchone()
        sequence, previous = row["sequence"] + 1, row["event_hash"]
        current = digest(sequence, previous, canonical)
        db.execute("INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?)", (
            sequence, canonical, previous, current, event.event_type, event.agent, event.decision,
        ))
        db.execute("UPDATE audit_head SET sequence=?, event_hash=? WHERE singleton=1", (sequence, current))

    def events(
        self, limit: int, after: int, event_type: EventType | None,
        agent: str | None, decision: Decision | None,
    ) -> list[AuditRecord]:
        with self.transaction() as db:
            rows = db.execute("""
                SELECT * FROM audit_events WHERE sequence > ?
                AND (? IS NULL OR event_type = ?) AND (? IS NULL OR agent = ?)
                AND (? IS NULL OR decision = ?) ORDER BY sequence LIMIT ?
            """, (after, event_type, event_type, agent, agent, decision, decision, limit)).fetchall()
        return [
            AuditRecord(
                **AuditEvent.model_validate_json(row["document"]).model_dump(),
                sequence=row["sequence"], previous_hash=row["previous_hash"], event_hash=row["event_hash"],
            )
            for row in rows
        ]

    def verify(self) -> ChainResult:
        with self.transaction() as db:
            return self.verify_connection(db)

    @staticmethod
    def verify_connection(db: sqlite3.Connection) -> ChainResult:
        last, previous = 0, GENESIS
        for row in db.execute("SELECT * FROM audit_events ORDER BY sequence"):
            sequence = last + 1
            try:
                event = json.loads(row["document"])
                metadata_valid = (event["event_type"], event["agent"], event["decision"]) == (
                    row["event_type"], row["agent"], row["decision"],
                )
            except (ValueError, TypeError, KeyError):
                metadata_valid = False
            if (
                not metadata_valid or row["sequence"] != sequence or row["previous_hash"] != previous
                or row["event_hash"] != digest(sequence, previous, row["document"])
            ):
                return ChainResult(valid=False, records_checked=last, failed_sequence=sequence)
            last, previous = sequence, row["event_hash"]
        head = db.execute("SELECT sequence, event_hash FROM audit_head WHERE singleton=1").fetchone()
        valid = head is not None and (last, previous) == (head["sequence"], head["event_hash"])
        return ChainResult(valid=valid, records_checked=last, failed_sequence=None if valid else last + 1)
