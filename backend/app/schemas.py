from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel
from sqlmodel import Field, SQLModel


class ImportJobRead(BaseModel):
    id: UUID
    filename: str
    sha256: str
    source: str
    host: Optional[str] = None
    user: Optional[str] = None
    events_ingested: int
    created_at: Optional[datetime] = None


class IncidentCreate(SQLModel):
    title: str
    severity: str = "medium"
    description: str = ""
    alert_ids: List[UUID] = Field(default_factory=list)


class IncidentRead(SQLModel):
    id: UUID
    created_at: datetime
    updated_at: datetime
    title: str
    severity: str
    status: str
    description: str


class IncidentLinkAlert(SQLModel):
    alert_id: UUID


class IncidentActionCreate(SQLModel):
    actor: Optional[str] = None
    action_type: str = "note"
    summary: str
    details: Optional[Dict[str, Any]] = None


class IncidentActionRead(SQLModel):
    id: UUID
    incident_id: UUID
    created_at: datetime
    actor: Optional[str] = None
    action_type: str
    summary: str
    details: Optional[Dict[str, Any]] = None
