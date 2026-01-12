from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ImportJob(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)

    filename: str
    sha256: str

    source: str = Field(index=True)
    host: Optional[str] = Field(default=None, index=True)
    user: Optional[str] = Field(default=None, index=True)

    events_ingested: int = 0


class Event(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    received_at: datetime = Field(default_factory=utc_now, index=True)

    source: str = Field(index=True)
    host: Optional[str] = Field(default=None, index=True)
    user: Optional[str] = Field(default=None, index=True)

    raw: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class Rule(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)

    name: str = Field(index=True)
    severity: str = Field(index=True)  # low, medium, high, critical
    mitre: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    description: str = ""

    match_source: str = Field(index=True)  # specific source, or "*" for any
    match_field: str = Field(index=True)   # supports dot paths like "event.action"
    match_contains: str


class Alert(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)

    rule_id: str = Field(index=True)
    rule_name: str = Field(index=True)
    severity: str = Field(index=True)

    event_id: str = Field(index=True)
    source: str = Field(index=True)
    host: Optional[str] = Field(default=None, index=True)
    user: Optional[str] = Field(default=None, index=True)

    summary: str


class Incident(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now, index=True)

    title: str = Field(index=True)
    severity: str = Field(index=True)  # low, medium, high, critical
    status: str = Field(default="open", index=True)  # open, closed
    description: str = Field(default="")


class IncidentAlert(SQLModel, table=True):
    incident_id: str = Field(primary_key=True, index=True)
    alert_id: str = Field(primary_key=True, index=True)
    added_at: datetime = Field(default_factory=utc_now, index=True)


class EvidenceFile(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    incident_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)

    filename: str = Field(index=True)
    content_type: str = Field(index=True)
    sha256: str = Field(index=True)
    size_bytes: int


class IncidentAction(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    incident_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)

    actor: Optional[str] = Field(default=None, index=True)
    action_type: str = Field(default="note", index=True)  # note, containment, eradication, recovery, comms
    summary: str
    details: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
