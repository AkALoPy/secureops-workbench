import { useEffect, useMemo, useState } from "react";
import { api, API_BASE } from "../lib/api";
import type { IncidentAction, IncidentPacket, EvidenceFile } from "../lib/api";
import { useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";

type TabKey = "overview" | "actions";

const actionTypes = [
  "note",
  "triage",
  "finding",
  "decision",
  "containment",
  "eradication",
  "recovery",
  "comms",
] as const;

function pill() {
  return "inline-flex items-center rounded-full bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700";
}

export function IncidentDetailPage() {
  const { id } = useParams();
  const incidentId = id as string;

  const [tab, setTab] = useState<TabKey>("overview");

  const [packet, setPacket] = useState<IncidentPacket | null>(null);
  const [evidence, setEvidence] = useState<EvidenceFile[]>([]);
  const [markdown, setMarkdown] = useState<string>("");

  const [actions, setActions] = useState<IncidentAction[]>([]);
  const [actionActor, setActionActor] = useState<string>("");
  const [actionType, setActionType] = useState<(typeof actionTypes)[number]>("note");
  const [actionSummary, setActionSummary] = useState<string>("");
  const [actionDetails, setActionDetails] = useState<string>("");

  const [loading, setLoading] = useState(true);
  const [savingAction, setSavingAction] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const actionCount = actions.length;

  async function refreshAll() {
    const [p, ev, acts] = await Promise.all([
      api.getIncidentPacket(incidentId),
      api.listEvidence(incidentId),
      api.listIncidentActions(incidentId),
    ]);

    setPacket(p);
    setEvidence(ev);
    setActions(acts);

    const mdRes = await fetch(`${API_BASE}/incidents/${incidentId}/report/markdown`);
    const mdText = await mdRes.text();
    setMarkdown(mdText);
  }

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        setErr(null);
        await refreshAll();
      } catch (e: unknown) {
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  const inc = packet?.incident;
  const scope = packet?.scope;

  const canSaveAction = useMemo(() => {
    return actionSummary.trim().length > 0 && !savingAction;
  }, [actionSummary, savingAction]);

  async function saveAction() {
    if (!canSaveAction) return;

    let detailsObj: Record<string, unknown> | null | undefined = undefined;

    const raw = actionDetails.trim();
    if (raw.length > 0) {
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        detailsObj = parsed;
      } catch {
        setErr("Action details must be valid JSON, or left empty.");
        return;
      }
    }

    try {
      setSavingAction(true);
      setErr(null);

      await api.createIncidentAction(incidentId, {
        actor: actionActor.trim() || undefined,
        action_type: actionType,
        summary: actionSummary.trim(),
        details: detailsObj ?? null,
      });

      setActionSummary("");
      setActionDetails("");
      setToast("Action added.");

      await refreshAll();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingAction(false);
    }
  }

  if (loading) return <div className="text-sm text-slate-600">Loading incident...</div>;
  if (err) {
    return (
      <div className="space-y-3">
        <div className="text-sm text-red-600">{err}</div>
        <button
          className="px-4 py-2 rounded-lg text-sm bg-white border hover:bg-slate-50"
          onClick={async () => {
            try {
              setErr(null);
              setLoading(true);
              await refreshAll();
            } catch (e: unknown) {
              setErr(e instanceof Error ? e.message : String(e));
            } finally {
              setLoading(false);
            }
          }}
        >
          Retry
        </button>
      </div>
    );
  }
  if (!packet || !inc || !scope) return <div className="text-sm text-slate-600">No data.</div>;

  return (
    <div className="space-y-5">
      {toast ? (
        <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-xl px-4 py-3 text-sm">
          {toast}
        </div>
      ) : null}

      <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">{inc.title}</h1>
          <div className="text-sm text-slate-600">
            {inc.status} • {inc.severity} • Created {new Date(inc.created_at).toLocaleString()}
          </div>
          {inc.description ? <div className="text-sm text-slate-700 mt-2">{inc.description}</div> : null}

            <div className="mt-3 flex flex-wrap gap-2">
            <span className={pill()}>Actions: {actionCount}</span>
            <span className={pill()}>Packet-driven reporting</span>
            <span className={pill()}>Evidence hashed</span>
          </div>
        </div>

        <div className="flex gap-2">
          <a
            className="px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200"
            href={`${API_BASE}/incidents/${incidentId}/report/markdown`}
            target="_blank"
            rel="noreferrer"
          >
            Open Markdown
          </a>
          <a
            className="px-4 py-2 rounded-lg text-sm bg-slate-900 text-white hover:bg-slate-800"
            href={`${API_BASE}/incidents/${incidentId}/report/pdf`}
            target="_blank"
            rel="noreferrer"
          >
            Download PDF
          </a>
        </div>
      </div>

      <div className="bg-white border rounded-2xl p-2 flex gap-2">
        <button
          className={`flex-1 px-4 py-2 rounded-xl text-sm font-medium ${
            tab === "overview" ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-50"
          }`}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
        <button
          className={`flex-1 px-4 py-2 rounded-xl text-sm font-medium ${
            tab === "actions" ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-50"
          }`}
          onClick={() => setTab("actions")}
        >
          Actions
        </button>
      </div>

      {tab === "actions" ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-white border rounded-2xl p-4 space-y-4">
            <div>
              <div className="font-semibold text-slate-900">Add action</div>
              <div className="text-sm text-slate-600">
                This becomes part of the incident packet and appears in Markdown and PDF exports.
              </div>
            </div>

            <div className="space-y-3">
              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Actor (optional)</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={actionActor}
                  onChange={(e) => setActionActor(e.target.value)}
                  placeholder="jpowers"
                />
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Type</div>
                <select
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={actionType}
                  onChange={(e) => setActionType(e.target.value as (typeof actionTypes)[number])}
                >
                  {actionTypes.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Summary</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={actionSummary}
                  onChange={(e) => setActionSummary(e.target.value)}
                  placeholder="Reviewed auth logs, confirmed repeated failures from single source IP."
                />
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Details (optional JSON)</div>
                <textarea
                  className="w-full border rounded-lg px-3 py-2 text-sm h-28 font-mono"
                  value={actionDetails}
                  onChange={(e) => setActionDetails(e.target.value)}
                  placeholder='{"src_ip":"203.0.113.10","attempts":42,"decision":"monitor"}'
                />
                <div className="text-xs text-slate-500 mt-1">
                  Leave empty if you do not need structured details.
                </div>
              </label>
            </div>

            <div className="flex justify-end gap-2">
              <button
                className="px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200"
                onClick={() => {
                  setActionSummary("");
                  setActionDetails("");
                }}
                disabled={savingAction}
              >
                Clear
              </button>
              <button
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  canSaveAction
                    ? "bg-slate-900 text-white hover:bg-slate-800"
                    : "bg-slate-200 text-slate-500 cursor-not-allowed"
                }`}
                onClick={saveAction}
                disabled={!canSaveAction}
              >
                {savingAction ? "Saving..." : "Add action"}
              </button>
            </div>
          </div>

          <div className="bg-white border rounded-2xl overflow-hidden lg:col-span-2">
            <div className="p-4 border-b flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-900">Action log</div>
                <div className="text-sm text-slate-600">Chronological case notes for auditability.</div>
              </div>
              <div className="text-xs text-slate-500">
                Total <span className="font-medium text-slate-900">{actions.length}</span>
              </div>
            </div>

            {actions.length === 0 ? (
              <div className="p-4 text-sm text-slate-600">No actions yet.</div>
            ) : (
              <div className="p-4 space-y-3">
                {actions.map((a) => (
                  <div key={a.id} className="border rounded-2xl p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs text-slate-500">
                        {new Date(a.created_at).toLocaleString()} •{" "}
                        <span className="font-medium text-slate-900">{a.action_type}</span>{" "}
                        {a.actor ? <>• {a.actor}</> : null}
                      </div>
                      <span className={pill()}>Logged</span>
                    </div>

                    <div className="mt-2 text-sm text-slate-900 font-medium">{a.summary}</div>

                    {a.details ? (
                      <pre className="mt-3 text-xs bg-slate-50 border rounded-xl p-3 overflow-auto">
                        {JSON.stringify(a.details, null, 2)}
                      </pre>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="bg-white border rounded-2xl p-4 space-y-2">
              <div className="font-semibold text-slate-900">Scope</div>
              <div className="text-sm text-slate-700 space-y-1">
                <div>
                  <span className="text-slate-500">Window:</span>{" "}
                  {new Date(scope.time_window.start).toLocaleString()} to{" "}
                  {new Date(scope.time_window.end).toLocaleString()}
                </div>
                <div>
                  <span className="text-slate-500">Hosts:</span>{" "}
                  {scope.hosts.length ? scope.hosts.join(", ") : "none"}
                </div>
                <div>
                  <span className="text-slate-500">Users:</span>{" "}
                  {scope.users.length ? scope.users.join(", ") : "none"}
                </div>
                <div>
                  <span className="text-slate-500">Sources:</span>{" "}
                  {scope.sources.length ? scope.sources.join(", ") : "none"}
                </div>
                <div>
                  <span className="text-slate-500">IPs:</span>{" "}
                  {scope.ips.length ? scope.ips.join(", ") : "none"}
                </div>
              </div>
            </div>

            <div className="bg-white border rounded-2xl p-4 space-y-2 lg:col-span-2">
              <div className="font-semibold text-slate-900">Evidence</div>
              {evidence.length === 0 ? (
                <div className="text-sm text-slate-600">No evidence files recorded.</div>
              ) : (
                <div className="space-y-2">
                  {evidence.map((e) => (
                    <div key={e.id} className="border rounded-2xl p-3">
                      <div className="text-sm font-medium text-slate-900">{e.filename}</div>
                      <div className="text-xs text-slate-600">SHA-256: {e.sha256}</div>
                      <div className="text-xs text-slate-600">
                        Size: {e.size_bytes} bytes • {new Date(e.created_at).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="bg-white border rounded-2xl overflow-hidden">
            <div className="p-4 border-b">
              <div className="font-semibold text-slate-900">Timeline</div>
              <div className="text-sm text-slate-600">
                Correlated events and alert activity in time order.
              </div>
            </div>
            <div className="p-4 space-y-2">
              {packet.timeline.slice(0, 200).map((t, idx) => (
                <div key={idx} className="border rounded-2xl p-3">
                  <div className="text-xs text-slate-500">
                    {new Date(t.time).toLocaleString()} • {t.type.toUpperCase()} •{" "}
                    {t.source ?? "n/a"}
                  </div>
                  <div className="text-sm text-slate-900">{t.summary}</div>
                  <div className="text-xs text-slate-600">
                    Host: {t.host ?? "n/a"} • User: {t.user ?? "n/a"}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white border rounded-2xl overflow-hidden">
            <div className="p-4 border-b">
              <div className="font-semibold text-slate-900">Report preview (Markdown)</div>
              <div className="text-sm text-slate-600">
                Generated live from the current incident packet, actions, and evidence records.
              </div>
            </div>
            <div className="p-4 prose max-w-none">
              <ReactMarkdown>{markdown}</ReactMarkdown>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
