from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4
import hashlib
import json
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlmodel import Session

from app.models import Event, ImportJob

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_safe(value: Any) -> Any:
    """
    Recursively convert Python objects into JSON-serializable types.
    This is required because CloudTrail lookup results contain datetime objects (ex: EventTime).
    """
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Decimal):
        # safer than float in many cases, but float is also acceptable for this project
        return float(value)

    if isinstance(value, (bytes, bytearray)):
        # CloudTrail data is generally UTF-8 safe, but protect against decode errors
        return value.decode("utf-8", errors="replace")

    if isinstance(value, dict):
        # JSON requires string keys
        return {str(k): _json_safe(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]

    # fallback, ensure we do not crash serialization
    return str(value)


def _assume_role_if_configured(base: boto3.Session, role_arn: str, region: str) -> boto3.Session:
    sts = base.client("sts", region_name=region)
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="secureops-workbench-cloudtrail-sync",
        DurationSeconds=3600,
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def sync_cloudtrail(session: Session, minutes: int = 15, region: Optional[str] = None) -> Dict[str, Any]:
    region = region or os.getenv("AWS_REGION") or "us-east-1"
    role_arn = os.getenv("AWS_ROLE_ARN")
    aws_profile = os.getenv("AWS_PROFILE")

    # boto3 default credential chain:
    # - env vars, shared config/profile (incl SSO), then instance role
    base = boto3.Session(profile_name=aws_profile, region_name=region)

    if role_arn:
        try:
            base = _assume_role_if_configured(base, role_arn=role_arn, region=region)
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(f"assume_role failed: {e}") from e

    client = base.client("cloudtrail", region_name=region)

    end_time = _utc_now()
    start_time = end_time - timedelta(minutes=minutes)

    events_raw: list[dict[str, Any]] = []
    try:
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start_time, EndTime=end_time, PaginationConfig={"PageSize": 50}):
            for ev in page.get("Events", []):
                cloudtrail_event_str = ev.get("CloudTrailEvent")
                parsed: dict[str, Any] = {}

                if isinstance(cloudtrail_event_str, str) and cloudtrail_event_str.strip():
                    try:
                        parsed = json.loads(cloudtrail_event_str)
                    except Exception:
                        parsed = {"raw_cloudtrail_event": cloudtrail_event_str}

                lookup_summary = {k: v for k, v in ev.items() if k != "CloudTrailEvent"}

                raw_obj = {
                    "lookup": lookup_summary,
                    "cloudtrail": parsed,
                }

                # Critical: sanitize before storing or writing JSONL
                events_raw.append(_json_safe(raw_obj))

    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"cloudtrail lookup_events failed: {e}") from e

    # Store as evidence like a real ingestion job
    job_id = str(uuid4())
    job_dir = EVIDENCE_DIR / "imports" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    filename = f"cloudtrail_{region}_{start_time.isoformat()}_{end_time.isoformat()}.jsonl".replace(":", "")
    jsonl_bytes = b"".join((json.dumps(x, ensure_ascii=False).encode("utf-8") + b"\n") for x in events_raw)
    sha = hashlib.sha256(jsonl_bytes).hexdigest()
    (job_dir / filename).write_bytes(jsonl_bytes)

    job = ImportJob(
        id=job_id,
        filename=filename,
        sha256=sha,
        source="aws-cloudtrail",
        host=None,
        user=None,
        events_ingested=len(events_raw),
    )
    session.add(job)

    # Ingest Events
    ingested = 0
    for obj in events_raw:
        ct = obj.get("cloudtrail") if isinstance(obj, dict) else {}
        username = None
        event_source = None

        if isinstance(ct, dict):
            ui = ct.get("userIdentity", {})
            if isinstance(ui, dict):
                username = ui.get("userName")
            event_source = ct.get("eventSource")

        payload = _json_safe(
            obj
            | {
                "_meta": {
                    "region": region,
                    "eventSource": event_source,
                }
            }
        )

        session.add(
            Event(
                source="aws-cloudtrail",
                host=None,
                user=username,
                raw=payload,
            )
        )
        ingested += 1

    session.commit()

    return {
        "events_ingested": ingested,
        "start": start_time.isoformat(),
        "end": end_time.isoformat(),
        "region": region,
    }
