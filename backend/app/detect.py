import json
from typing import Any, Optional

from sqlmodel import Session, select

from .models import Alert, Event, Rule


def _get_by_path(obj: Any, path: str) -> Optional[Any]:
    """
    Supports dot paths, ex: "event.action", against dict-like JSON.
    """
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def run_detections(session: Session, limit: int = 500) -> int:
    rules = session.exec(select(Rule).order_by(Rule.created_at.desc())).all()
    if not rules:
        return 0

    events = session.exec(select(Event).order_by(Event.received_at.desc()).limit(limit)).all()
    created = 0

    for ev in events:
        for r in rules:
            if r.match_source and r.match_source != "*" and r.match_source != ev.source:
                continue

            value = _get_by_path(ev.raw, r.match_field)
            if value is None:
                continue

            haystack = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            if r.match_contains.lower() not in haystack.lower():
                continue

            existing = session.exec(
                select(Alert).where(Alert.event_id == ev.id).where(Alert.rule_id == r.id)
            ).first()
            if existing:
                continue

            summary = f"{r.name}: {r.match_field} matched '{r.match_contains}'"
            session.add(
                Alert(
                    rule_id=r.id,
                    rule_name=r.name,
                    severity=r.severity,
                    event_id=ev.id,
                    source=ev.source,
                    host=ev.host,
                    user=ev.user,
                    summary=summary,
                )
            )
            created += 1

    if created:
        session.commit()

    return created
