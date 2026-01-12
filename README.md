# SecureOps Workbench
SecureOps Workbench is a local-first cyber security workflow app that ingests events, runs detections, generates alerts, and supports incident tracking with evidence packaging and report export.

## Alerts
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Alerts.png" />

## Incidents
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Incidents.png" />

## Creating Incidents
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Creating%20incidents.png" />


## Exporting Incident Reports to PDF/Markdown
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Incident-Report-Investigate-Linux.png" />

## Securty Investigation
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Security%20investigation.png" />

## Securty Investigation 2
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/Security%20investigation%202.png" />

## Imports /w Cloudtrail Support
<img width="1173" height="832" alt="Alerts" src="https://github.com/AkALoPy/secureops-workbench/blob/master/screenshots/frontend.png" />



This repo is intended for cyber security engineers and continued learning use.

## What it does

- Ingests events (JSON payloads or JSONL bulk imports)
- Runs detections to create alerts
- Creates incidents and links alerts to incidents
- Records incident actions
- Exports incident packets and reports (Markdown and PDF)

## Architecture

- Backend: FastAPI + SQLModel
- Frontend: Vite + React + TypeScript
- Storage: local SQLite (development) + Docker
- Optional connector: AWS CloudTrail sync for recent events

## Prerequisites

- Python 3.11+ (your environment may differ)
- Node.js 18+
- Git

Optional:
- AWS CLI configured with a profile
- GitHub CLI, https://cli.github.com/

## Local setup

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set ADMIN_API_KEY in backend/.env or export it in your shell
uvicorn app.main:app --reload --port 8000
```

## Health check:
```bash
curl -i http://127.0.0.1:8000/health
```

## Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Frontend dev server typically runs at:
http://127.0.0.1:5173

# Run with Docker (Postgres)

This project includes a `docker-compose.yml` for local Postgres.

### Prerequisites
- Docker Desktop
- (Optional) psql if you want to inspect the DB locally

### 1) Configure environment variables
Copy the example env file and set a local password:

```bash
cp .env.example .env
# edit .env and set POSTGRES_PASSWORD
```

## Start Postgres
```bash
docker compose up -d postgres
docker compose ps
```


## API authentication

Most endpoints require X-API-Key.

Example:
```bash
curl -i -X GET "http://127.0.0.1:8000/alerts" \
  -H "X-API-Key: YOUR_ADMIN_API_KEY"
```
## CloudTrail sync (optional)

If configured, the backend can pull recent CloudTrail management events.

Example:
```bash
curl -i -X POST "http://127.0.0.1:8000/connectors/aws/cloudtrail/sync?minutes=5&region=us-east-1" \
  -H "X-API-Key: YOUR_ADMIN_API_KEY"
```

Notes:

This repo does not launch with CloudTrail exports checked in.

If you add sample CloudTrail data for demonstration, sanitize account IDs, IPs, user agents, and access key identifiers.

Incident workflow (typical)

Ingest events (import JSONL or post events)

Run detections to generate alerts

Create an incident and link relevant alerts

Add incident actions as you investigate

Export an incident packet, then export Markdown or PDF report
