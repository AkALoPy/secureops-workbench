from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
import hashlib
import json

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from sqlmodel import Session, select

from app.auth import require_admin_api_key
from app.connectors.aws_cloudtrail import sync_cloudtrail

from .db import get_session, init_db
from .detect import run_detections
from .models import (
    Alert,
    EvidenceFile,
    Event,
    ImportJob,
    Incident,
    IncidentAlert,
    IncidentAction,
    Rule,
)
from .reporting import (
    build_incident_packet,
    render_markdown,
    render_pdf,
    write_packet_evidence,
)
from .schemas import (
    ImportJobRead,
    IncidentActionCreate,
    IncidentActionRead,
    IncidentCreate,
    IncidentLinkAlert,
    IncidentRead,
)

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SecureOps Workbench", version="0.3.0")


# Frontend dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# Keep health open (no auth) so you can quickly verify server is up.
@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


# -----------------------------
# AWS connector: CloudTrail
# -----------------------------
@app.post("/connectors/aws/cloudtrail/sync", dependencies=[Depends(require_admin_api_key)])
def cloudtrail_sync(
    minutes: int = Query(15, ge=1, le=1440),
    region: str | None = None,
    session: Session = Depends(get_session),
):
    return sync_cloudtrail(session=session, minutes=minutes, region=region)


# -----------------------------
# Alerts
# -----------------------------
@app.get("/alerts", response_model=List[Alert])
def list_alerts(
    limit: int = 100,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[Alert]:
    return session.exec(select(Alert).order_by(Alert.created_at.desc()).limit(limit)).all()


@app.delete("/alerts/{alert_id}")
def delete_alert(
    alert_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> dict:
    a = session.exec(select(Alert).where(Alert.id == alert_id)).first()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")

    # remove incident links
    links = session.exec(select(IncidentAlert).where(IncidentAlert.alert_id == alert_id)).all()
    for x in links:
        session.delete(x)

    session.delete(a)
    session.commit()
    return {"status": "deleted"}


# -----------------------------
# Imports (bulk ingestion)
# -----------------------------
@app.post("/imports/jsonl", response_model=ImportJobRead)
async def import_jsonl(
    file: UploadFile = File(...),
    source: str = Query(...),
    host: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> ImportJob:
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()

    job_id = str(uuid4())
    job_dir = EVIDENCE_DIR / "imports" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    filename = file.filename or "upload.jsonl"
    (job_dir / filename).write_bytes(data)

    events: list[Event] = []
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8") if isinstance(line, (bytes, bytearray)) else line)
        except Exception:
            continue
        events.append(Event(source=source, host=host, user=user, raw=obj))

    job = ImportJob(
        id=job_id,
        filename=filename,
        sha256=sha,
        source=source,
        host=host,
        user=user,
        events_ingested=len(events),
    )

    session.add(job)
    for ev in events:
        session.add(ev)
    session.commit()
    session.refresh(job)

    return job


@app.get("/imports", response_model=List[ImportJobRead])
def list_imports(
    limit: int = 50,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[ImportJob]:
    return session.exec(select(ImportJob).order_by(ImportJob.created_at.desc()).limit(limit)).all()


@app.delete("/imports/{import_id}")
def delete_import(
    import_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> dict:
    j = session.exec(select(ImportJob).where(ImportJob.id == import_id)).first()
    if not j:
        raise HTTPException(status_code=404, detail="import not found")
    session.delete(j)
    session.commit()
    return {"status": "deleted"}


# -----------------------------
# Events / Rules / Detections
# -----------------------------
@app.post("/events", response_model=Event)
def ingest_event(
    payload: Dict[str, Any],
    source: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Event:
    ev = Event(source=source, host=host, user=user, raw=payload)
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


@app.get("/events", response_model=List[Event])
def list_events(
    limit: int = 50,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[Event]:
    return session.exec(select(Event).order_by(Event.received_at.desc()).limit(limit)).all()


@app.post("/rules", response_model=Rule)
def create_rule(
    rule: Rule,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Rule:
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@app.get("/rules", response_model=List[Rule])
def list_rules(
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[Rule]:
    return session.exec(select(Rule).order_by(Rule.created_at.desc())).all()


@app.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> dict:
    r = session.exec(select(Rule).where(Rule.id == rule_id)).first()
    if not r:
        raise HTTPException(status_code=404, detail="rule not found")
    session.delete(r)
    session.commit()
    return {"status": "deleted"}


@app.post("/detections/run")
def run(
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Dict[str, int]:
    created = run_detections(session=session, limit=500)
    return {"alerts_created": created}


# -----------------------------
# Incidents
# -----------------------------
@app.post("/incidents", response_model=IncidentRead)
def create_incident(
    incident_in: IncidentCreate,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Incident:
    inc = Incident(
        title=incident_in.title,
        severity=incident_in.severity,
        description=incident_in.description,
    )
    session.add(inc)
    session.commit()
    session.refresh(inc)

    if incident_in.alert_ids:
        for alert_id in incident_in.alert_ids:
            a = session.exec(select(Alert).where(Alert.id == alert_id)).first()
            if not a:
                continue
            session.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        session.commit()

    return inc


@app.get("/incidents", response_model=List[IncidentRead])
def list_incidents(
    limit: int = 50,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[Incident]:
    return session.exec(select(Incident).order_by(Incident.created_at.desc()).limit(limit)).all()


@app.get("/incidents/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Incident:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    return inc


@app.delete("/incidents/{incident_id}")
def delete_incident(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> dict:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    links = session.exec(select(IncidentAlert).where(IncidentAlert.incident_id == incident_id)).all()
    actions = session.exec(select(IncidentAction).where(IncidentAction.incident_id == incident_id)).all()
    for x in links:
        session.delete(x)
    for x in actions:
        session.delete(x)

    session.delete(inc)
    session.commit()
    return {"status": "deleted"}


@app.get("/incidents/{incident_id}/packet")
def get_incident_packet(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Dict[str, Any]:
    try:
        return build_incident_packet(session=session, incident_id=incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="incident not found")


@app.post("/incidents/{incident_id}/alerts")
def add_alert_to_incident(
    incident_id: str,
    payload: IncidentLinkAlert,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Dict[str, str]:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    a = session.exec(select(Alert).where(Alert.id == payload.alert_id)).first()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")

    existing = session.exec(
        select(IncidentAlert)
        .where(IncidentAlert.incident_id == incident_id)
        .where(IncidentAlert.alert_id == payload.alert_id)
    ).first()
    if existing:
        return {"status": "already-linked"}

    session.add(IncidentAlert(incident_id=incident_id, alert_id=payload.alert_id))
    inc.updated_at = utc_now()
    session.add(inc)
    session.commit()
    return {"status": "linked"}


@app.post("/incidents/{incident_id}/actions", response_model=IncidentActionRead)
def create_incident_action(
    incident_id: str,
    payload: IncidentActionCreate,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> IncidentAction:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    action = IncidentAction(
        incident_id=incident_id,
        actor=payload.actor,
        action_type=payload.action_type,
        summary=payload.summary,
        details=payload.details,
    )
    session.add(action)

    inc.updated_at = utc_now()
    session.add(inc)

    session.commit()
    session.refresh(action)
    return action


@app.get("/incidents/{incident_id}/actions", response_model=List[IncidentActionRead])
def list_incident_actions(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[IncidentAction]:
    return session.exec(
        select(IncidentAction)
        .where(IncidentAction.incident_id == incident_id)
        .order_by(IncidentAction.created_at.desc())
    ).all()


@app.post("/incidents/{incident_id}/close", response_model=IncidentRead)
def close_incident(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Incident:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    inc.status = "closed"
    inc.updated_at = utc_now()
    session.add(inc)
    session.commit()
    session.refresh(inc)
    return inc


@app.get("/incidents/{incident_id}/evidence", response_model=List[EvidenceFile])
def list_evidence(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> List[EvidenceFile]:
    return session.exec(
        select(EvidenceFile).where(EvidenceFile.incident_id == incident_id).order_by(EvidenceFile.created_at.desc())
    ).all()


@app.get("/incidents/{incident_id}/report/markdown")
def export_markdown(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> Response:
    packet = build_incident_packet(session=session, incident_id=incident_id)
    evidence = write_packet_evidence(session=session, incident_id=incident_id, packet=packet)
    md = render_markdown(packet=packet, evidence=evidence)
    return Response(content=md, media_type="text/markdown")


@app.get("/incidents/{incident_id}/report/pdf")
def export_pdf(
    incident_id: str,
    session: Session = Depends(get_session),
    _admin: None = Depends(require_admin_api_key),
) -> StreamingResponse:
    packet = build_incident_packet(session=session, incident_id=incident_id)
    evidence = write_packet_evidence(session=session, incident_id=incident_id, packet=packet)
    pdf_bytes = render_pdf(packet=packet, evidence=evidence)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="incident-report.pdf"'},
    )
