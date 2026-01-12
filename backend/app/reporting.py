from __future__ import annotations

from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
import json

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

from sqlmodel import Session, select

from .models import (
    Alert,
    EvidenceFile,
    Event,
    Incident,
    IncidentAction,
    IncidentAlert,
)


EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _safe_iso(dt: Any) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def _event_summary(raw: Dict[str, Any]) -> str:
    # Try common fields first, otherwise keep a short JSON snippet.
    for k in ("message", "summary", "event", "msg", "log", "description"):
        v = raw.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()[:220]
    try:
        s = json.dumps(raw, ensure_ascii=False)
        return s[:220]
    except Exception:
        return str(raw)[:220]


def _extract_ips(raw: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    keys = ("src_ip", "source_ip", "client_ip", "remote_ip", "ip", "src", "dst_ip", "dest_ip")
    for k in keys:
        v = raw.get(k)
        if isinstance(v, str) and v.strip():
            ips.append(v.strip())
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    ips.append(item.strip())
    # De-dupe while preserving order
    seen = set()
    out: List[str] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def build_incident_packet(session: Session, incident_id: str) -> Dict[str, Any]:
    inc = session.exec(select(Incident).where(Incident.id == incident_id)).first()
    if not inc:
        raise ValueError("incident not found")

    alerts = session.exec(
        select(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .where(IncidentAlert.incident_id == incident_id)
        .order_by(Alert.created_at.asc())
    ).all()

    actions = session.exec(
        select(IncidentAction)
        .where(IncidentAction.incident_id == incident_id)
        .order_by(IncidentAction.created_at.asc())
    ).all()

    # Batch fetch related events for alert timeline enrichment
    event_ids = [a.event_id for a in alerts if a.event_id]
    events_by_id: Dict[str, Event] = {}
    if event_ids:
        evs = session.exec(select(Event).where(Event.id.in_(event_ids))).all()
        events_by_id = {e.id: e for e in evs}

    # Scope
    times: List[datetime] = []
    hosts: List[str] = []
    users: List[str] = []
    sources: List[str] = []
    ips: List[str] = []

    for a in alerts:
        times.append(a.created_at)
        if a.host:
            hosts.append(a.host)
        if a.user:
            users.append(a.user)
        if a.source:
            sources.append(a.source)

        ev = events_by_id.get(a.event_id)
        if ev:
            times.append(ev.received_at)
            if ev.host:
                hosts.append(ev.host)
            if ev.user:
                users.append(ev.user)
            if ev.source:
                sources.append(ev.source)
            if isinstance(ev.raw, dict):
                ips.extend(_extract_ips(ev.raw))

    if not times:
        start = inc.created_at
        end = inc.updated_at
    else:
        start = min(times)
        end = max(times)

    def _uniq(items: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in items:
            if not x:
                continue
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    scope = {
        "time_window": {"start": _safe_iso(start), "end": _safe_iso(end)},
        "hosts": _uniq(hosts),
        "users": _uniq(users),
        "sources": _uniq(sources),
        "ips": _uniq(ips),
    }

    # Timeline: alerts plus (if available) raw event ingest records.
    timeline: List[Dict[str, Any]] = []
    for a in alerts:
        timeline.append(
            {
                "time": _safe_iso(a.created_at),
                "type": "alert",
                "source": a.source,
                "host": a.host,
                "user": a.user,
                "summary": f"[{a.severity}] {a.rule_name}: {a.summary}",
            }
        )
        ev = events_by_id.get(a.event_id)
        if ev and isinstance(ev.raw, dict):
            timeline.append(
                {
                    "time": _safe_iso(ev.received_at),
                    "type": "event",
                    "source": ev.source,
                    "host": ev.host,
                    "user": ev.user,
                    "summary": _event_summary(ev.raw),
                }
            )

    timeline.sort(key=lambda t: t["time"])

    packet = {
        "incident": {
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "created_at": _safe_iso(inc.created_at),
            "updated_at": _safe_iso(inc.updated_at),
            "description": inc.description,
        },
        "scope": scope,
        "alerts": [
            {
                "id": a.id,
                "created_at": _safe_iso(a.created_at),
                "severity": a.severity,
                "rule_name": a.rule_name,
                "summary": a.summary,
                "event_id": a.event_id,
                "host": a.host,
                "user": a.user,
                "source": a.source,
            }
            for a in alerts
        ],
        "timeline": timeline,
        "actions": [
            {
                "id": act.id,
                "incident_id": act.incident_id,
                "created_at": _safe_iso(act.created_at),
                "actor": act.actor,
                "action_type": act.action_type,
                "summary": act.summary,
                "details": act.details,
            }
            for act in actions
        ],
    }

    return packet


def write_packet_evidence(session: Session, incident_id: str, packet: Dict[str, Any]) -> List[EvidenceFile]:
    incident_dir = EVIDENCE_DIR / incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)

    filename_rel = f"{incident_id}/incident-packet.json"
    file_path = incident_dir / "incident-packet.json"

    payload = json.dumps(packet, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    sha = hashlib.sha256(payload).hexdigest()
    size = len(payload)

    file_path.write_bytes(payload)

    existing = session.exec(
        select(EvidenceFile)
        .where(EvidenceFile.incident_id == incident_id)
        .where(EvidenceFile.filename == filename_rel)
        .where(EvidenceFile.sha256 == sha)
    ).first()

    if not existing:
        ef = EvidenceFile(
            incident_id=incident_id,
            filename=filename_rel,
            content_type="application/json",
            sha256=sha,
            size_bytes=size,
        )
        session.add(ef)
        session.commit()

    # Return latest evidence list
    return session.exec(
        select(EvidenceFile)
        .where(EvidenceFile.incident_id == incident_id)
        .order_by(EvidenceFile.created_at.desc())
    ).all()


def render_markdown(packet: Dict[str, Any], evidence: List[EvidenceFile]) -> str:
    inc = packet["incident"]
    scope = packet["scope"]
    actions = packet.get("actions", [])
    timeline = packet.get("timeline", [])

    lines: List[str] = []
    lines.append(f"# Incident Report: {inc['title']}")
    lines.append("")
    lines.append(f"- **Incident ID:** {inc['id']}")
    lines.append(f"- **Status:** {inc['status']}")
    lines.append(f"- **Severity:** {inc['severity']}")
    lines.append(f"- **Created:** {inc['created_at']}")
    lines.append(f"- **Updated:** {inc['updated_at']}")
    if inc.get("description"):
        lines.append(f"- **Description:** {inc['description']}")
    lines.append("")

    lines.append("## Scope")
    lines.append(f"- **Window:** {scope['time_window']['start']} to {scope['time_window']['end']}")
    lines.append(f"- **Hosts:** {', '.join(scope['hosts']) if scope['hosts'] else 'none'}")
    lines.append(f"- **Users:** {', '.join(scope['users']) if scope['users'] else 'none'}")
    lines.append(f"- **Sources:** {', '.join(scope['sources']) if scope['sources'] else 'none'}")
    lines.append(f"- **IPs:** {', '.join(scope['ips']) if scope['ips'] else 'none'}")
    lines.append("")

    lines.append("## Actions (Investigation Log)")
    if not actions:
        lines.append("_No actions recorded._")
    else:
        for a in actions:
            actor = a.get("actor") or "unknown"
            atype = a.get("action_type") or "note"
            ts = a.get("created_at")
            summary = a.get("summary") or ""
            lines.append(f"- **{ts}** [{atype}] ({actor}) {summary}")
            details = a.get("details")
            if isinstance(details, dict) and details:
                try:
                    detail_json = json.dumps(details, indent=2, ensure_ascii=False)
                except Exception:
                    # Fall back to a JSON string that serializes non-standard types using str()
                    detail_json = json.dumps(details, indent=2, ensure_ascii=False, default=str)
                lines.append("")
                lines.append("```json")
                lines.append(detail_json)
                lines.append("```")
                lines.append("")
    lines.append("")

    lines.append("## Timeline")
    if not timeline:
        lines.append("_No timeline entries._")
    else:
        for t in timeline[:500]:
            ts = t.get("time")
            typ = (t.get("type") or "").upper()
            src = t.get("source") or "n/a"
            host = t.get("host") or "n/a"
            user = t.get("user") or "n/a"
            summary = t.get("summary") or ""
            lines.append(f"- **{ts}** {typ} src={src} host={host} user={user} , {summary}")
    lines.append("")

    lines.append("## Evidence")
    if not evidence:
        lines.append("_No evidence files recorded._")
    else:
        for e in evidence:
            lines.append(f"- {e.filename} (sha256={e.sha256}, size={e.size_bytes} bytes, created={e.created_at})")

    lines.append("")
    return "\n".join(lines)


def render_pdf(packet: Dict[str, Any], evidence: List[EvidenceFile]) -> bytes:
    inc = packet["incident"]
    scope = packet["scope"]
    actions = packet.get("actions", [])
    timeline = packet.get("timeline", [])

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, title=f"Incident Report - {inc['title']}")
    styles = getSampleStyleSheet()
    story: List[Any] = []

    story.append(Paragraph(f"Incident Report: {inc['title']}", styles["Title"]))
    story.append(Spacer(1, 10))

    meta_data = [
        ["Incident ID", inc["id"]],
        ["Status", inc["status"]],
        ["Severity", inc["severity"]],
        ["Created", inc["created_at"]],
        ["Updated", inc["updated_at"]],
    ]
    if inc.get("description"):
        meta_data.append(["Description", inc["description"]])

    t = Table(meta_data, colWidths=[120, 420])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scope", styles["Heading2"]))
    story.append(Spacer(1, 4))
    scope_tbl = Table(
        [
            ["Window", f"{scope['time_window']['start']} to {scope['time_window']['end']}"],
            ["Hosts", ", ".join(scope["hosts"]) if scope["hosts"] else "none"],
            ["Users", ", ".join(scope["users"]) if scope["users"] else "none"],
            ["Sources", ", ".join(scope["sources"]) if scope["sources"] else "none"],
            ["IPs", ", ".join(scope["ips"]) if scope["ips"] else "none"],
        ],
        colWidths=[120, 420],
    )
    scope_tbl.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(scope_tbl)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Actions (Investigation Log)", styles["Heading2"]))
    story.append(Spacer(1, 6))
    if not actions:
        story.append(Paragraph("No actions recorded.", styles["BodyText"]))
    else:
        for a in actions[:200]:
            actor = a.get("actor") or "unknown"
            atype = a.get("action_type") or "note"
            ts = a.get("created_at")
            summary = a.get("summary") or ""
            story.append(Paragraph(f"{ts}  [{atype}]  ({actor})  {summary}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Timeline", styles["Heading2"]))
    story.append(Spacer(1, 6))
    if not timeline:
        story.append(Paragraph("No timeline entries.", styles["BodyText"]))
    else:
        for titem in timeline[:250]:
            ts = titem.get("time")
            typ = (titem.get("type") or "").upper()
            src = titem.get("source") or "n/a"
            host = titem.get("host") or "n/a"
            user = titem.get("user") or "n/a"
            summary = titem.get("summary") or ""
            story.append(
                Paragraph(f"{ts}  {typ}  src={src}  host={host}  user={user} , {summary}", styles["BodyText"])
            )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Evidence", styles["Heading2"]))
    story.append(Spacer(1, 6))
    if not evidence:
        story.append(Paragraph("No evidence files recorded.", styles["BodyText"]))
    else:
        for e in evidence[:200]:
            story.append(
                Paragraph(
                    f"{e.filename}  sha256={e.sha256}  size={e.size_bytes} bytes  created={_safe_iso(e.created_at)}",
                    styles["BodyText"],
                )
            )

    doc.build(story)
    return buf.getvalue()
