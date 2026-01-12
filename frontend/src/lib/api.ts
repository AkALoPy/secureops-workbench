export const API_BASE =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://127.0.0.1:8000";

export type Alert = {
  id: string;
  created_at: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  event_id: string;
  source: string;
  host?: string | null;
  user?: string | null;
  summary: string;
};

export type ImportJob = {
  id: string;
  filename: string;
  sha256: string;
  source: string;
  host?: string | null;
  user?: string | null;
  events_ingested: number;
  created_at?: string | null;
};

export type Incident = {
  id: string;
  created_at: string;
  updated_at: string;
  title: string;
  severity: string;
  status: string;
  description: string;
};

export type EvidenceFile = {
  id: string;
  incident_id: string;
  created_at: string;
  filename: string;
  content_type: string;
  sha256: string;
  size_bytes: number;
};

export type IncidentPacket = {
  incident: {
    id: string;
    title: string;
    severity: string;
    status: string;
    created_at: string;
    updated_at: string;
    description: string;
  };
  scope: {
    time_window: { start: string; end: string };
    hosts: string[];
    users: string[];
    sources: string[];
    ips: string[];
  };
  alerts: Array<{
    id: string;
    created_at: string;
    severity: string;
    rule_name: string;
    summary: string;
    event_id: string;
    host?: string | null;
    user?: string | null;
    source: string;
  }>;
  timeline: Array<{
    time: string;
    type: string;
    source?: string;
    host?: string | null;
    user?: string | null;
    summary: string;
  }>;
};

export type Rule = {
  id: string;
  created_at: string;
  name: string;
  severity: string;
  mitre: string[];
  description: string;
  match_source: string;
  match_field: string;
  match_contains: string;
};

export type IncidentActionType = "note" | "containment" | "eradication" | "recovery" | "comms";

export type IncidentAction = {
  id: string;
  incident_id: string;
  created_at: string;
  actor?: string | null;
  action_type: IncidentActionType;
  summary: string;
  details?: Record<string, unknown> | null;
};

type JsonInit = Omit<RequestInit, "body"> & { body?: unknown };

function adminHeaders(): Record<string, string> {
  const key = localStorage.getItem("admin_api_key");
  return key ? { "X-API-Key": key } : {};
}

async function http<T>(path: string, init?: JsonInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
      ...(init?.headers ?? {}),
    },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });

  const contentType = res.headers.get("content-type") ?? "";

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText} from ${url}: ${text.slice(0, 300)}`);
  }

  if (!contentType.includes("application/json")) {
    const text = await res.text();
    throw new Error(`Expected JSON from ${url}, got ${contentType}. Body starts: ${text.slice(0, 80)}`);
  }

  return (await res.json()) as T;
}

export async function importJsonl(
  file: File,
  params: { source: string; host?: string; user?: string }
): Promise<ImportJob> {
  const form = new FormData();
  form.append("file", file);

  const qs = new URLSearchParams();
  qs.set("source", params.source);
  if (params.host) qs.set("host", params.host);
  if (params.user) qs.set("user", params.user);

  const res = await fetch(`${API_BASE}/imports/jsonl?${qs.toString()}`, {
    method: "POST",
    headers: {
      ...adminHeaders(),
    },
    body: form,
  });

  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

type DeleteResponse = { status: "ok" | "deleted" | string };

export const api = {
  // Alerts
  listAlerts: () => http<Alert[]>("/alerts"),
  deleteAlert: (id: string) => http<DeleteResponse>(`/alerts/${id}`, { method: "DELETE" }),

  // Imports
  listImports: () => http<ImportJob[]>("/imports"),
  importJsonl,
  deleteImportJob: (id: string) => http<DeleteResponse>(`/imports/${id}`, { method: "DELETE" }),
  runDetections: () => http<{ alerts_created: number }>("/detections/run", { method: "POST" }),

  // AWS connectors (CloudTrail)
  syncAwsCloudTrail: (params?: { minutes?: number; region?: string }) => {
    const qs = new URLSearchParams();
    if (params?.minutes) qs.set("minutes", String(params.minutes));
    if (params?.region) qs.set("region", params.region);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return http<{ events_ingested: number; start: string; end: string; region: string }>(
      `/connectors/aws/cloudtrail/sync${suffix}`,
      { method: "POST" }
    );
  },

  // Rules
  listRules: () => http<Rule[]>("/rules"),
  createRule: (payload: {
    name: string;
    severity: string;
    mitre?: string[];
    description?: string;
    match_source: string;
    match_field: string;
    match_contains: string;
  }) => http<Rule>("/rules", { method: "POST", body: { mitre: [], description: "", ...payload } }),
  deleteRule: (id: string) => http<DeleteResponse>(`/rules/${id}`, { method: "DELETE" }),

  // Incidents
  listIncidents: () => http<Incident[]>("/incidents"),
  getIncident: (id: string) => http<Incident>(`/incidents/${id}`),
  getIncidentPacket: (id: string) => http<IncidentPacket>(`/incidents/${id}/packet`),
  listEvidence: (id: string) => http<EvidenceFile[]>(`/incidents/${id}/evidence`),

  createIncident: (payload: { title: string; severity: string; description: string; alert_ids: string[] }) =>
    http<Incident>("/incidents", { method: "POST", body: payload }),

  deleteIncident: (id: string) => http<DeleteResponse>(`/incidents/${id}`, { method: "DELETE" }),
  closeIncident: (id: string) => http<Incident>(`/incidents/${id}/close`, { method: "POST" }),

  // Incident actions
  listIncidentActions: (incidentId: string) => http<IncidentAction[]>(`/incidents/${incidentId}/actions`),
  createIncidentAction: (
    incidentId: string,
    payload: { actor?: string; action_type: IncidentActionType; summary: string; details?: Record<string, unknown> }
  ) => http<IncidentAction>(`/incidents/${incidentId}/actions`, { method: "POST", body: payload }),
};
