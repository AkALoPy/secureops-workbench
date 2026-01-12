import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { api } from "../lib/api";
import type { Alert, IncidentActionType } from "../lib/api";
import { useNavigate } from "react-router-dom";

const severities = ["all", "low", "medium", "high", "critical"] as const;
type SeverityFilter = (typeof severities)[number];

const actionTypes: IncidentActionType[] = ["note", "containment", "eradication", "recovery", "comms"];
const refreshOptionsSec = [5, 10, 20, 30, 60] as const;

function severityRank(s: string): number {
  switch (s) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function severityPillClass(s: string) {
  switch (s) {
    case "critical":
      return "bg-rose-100 text-rose-900 border border-rose-200";
    case "high":
      return "bg-orange-100 text-orange-900 border border-orange-200";
    case "medium":
      return "bg-sky-100 text-sky-900 border border-sky-200";
    case "low":
      return "bg-emerald-100 text-emerald-900 border border-emerald-200";
    default:
      return "bg-slate-100 text-slate-900 border border-slate-200";
  }
}

function formatTime(d: Date) {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const alertsRef = useRef<Alert[]>([]);
  useEffect(() => {
    alertsRef.current = alerts;
  }, [alerts]);

  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [query, setQuery] = useState("");

  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const selectedIds = useMemo(() => Object.keys(selected).filter((k) => selected[k]), [selected]);

  const [showCreate, setShowCreate] = useState(false);

  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshEverySec, setRefreshEverySec] = useState<(typeof refreshOptionsSec)[number]>(10);
  const [newSinceRefresh, setNewSinceRefresh] = useState(0);

  const [createTitle, setCreateTitle] = useState("Security investigation");
  const [createDescription, setCreateDescription] = useState("");
  const [createSeverity, setCreateSeverity] = useState<Exclude<SeverityFilter, "all">>("medium");
  const [creating, setCreating] = useState(false);

  // optional initial incident action
  const [createActionActor, setCreateActionActor] = useState("");
  const [createActionType, setCreateActionType] = useState<IncidentActionType>("note");
  const [createActionSummary, setCreateActionSummary] = useState("");

  // delete state
  const [deletingBulk, setDeletingBulk] = useState(false);
  const [deletingOne, setDeletingOne] = useState<string | null>(null);

  const nav = useNavigate();

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (severity !== "all" && a.severity !== severity) return false;
      if (!q) return true;
      const hay = `${a.rule_name} ${a.summary} ${a.host ?? ""} ${a.user ?? ""} ${a.source}`.toLowerCase();
      return hay.includes(q);
    });
  }, [alerts, severity, query]);

  const allFilteredSelected = useMemo(() => {
    if (filtered.length === 0) return false;
    return filtered.every((a) => selected[a.id]);
  }, [filtered, selected]);

  const someFilteredSelected = useMemo(() => {
    if (filtered.length === 0) return false;
    return filtered.some((a) => selected[a.id]);
  }, [filtered, selected]);

  async function refreshAlerts(markNew: boolean) {
    try {
      setErr(null);
      const data = await api.listAlerts();

      if (markNew) {
        const prevIds = new Set(alertsRef.current.map((a) => a.id));
        let newCount = 0;
        for (const a of data) {
          if (!prevIds.has(a.id)) newCount += 1;
        }
        if (newCount > 0) setNewSinceRefresh((prev) => prev + newCount);
      } else {
        setNewSinceRefresh(0);
      }

      setAlerts(data);
      setLastUpdated(new Date());
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    (async () => {
      setLoading(true);
      await refreshAlerts(false);
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;

    const t = window.setInterval(() => {
      refreshAlerts(true);
    }, refreshEverySec * 1000);

    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, refreshEverySec]);

  useEffect(() => {
    if (!showCreate) return;

    const ids = selectedIds;
    const selectedAlerts = alerts.filter((a) => ids.includes(a.id));
    const best = selectedAlerts.reduce(
      (acc, a) => (severityRank(a.severity) > severityRank(acc) ? a.severity : acc),
      "medium"
    );

    const sev = (best === "all" ? "medium" : best) as Exclude<SeverityFilter, "all">;
    setCreateSeverity(sev);

    setCreateTitle(selectedAlerts.length === 1 ? `Investigate: ${selectedAlerts[0].rule_name}` : "Security investigation");
    setCreateDescription(`Created from ${ids.length} alert(s) in SecureOps Workbench.`);

    const ruleNames = selectedAlerts.slice(0, 5).map((a) => a.rule_name).join(", ");
    const more = selectedAlerts.length > 5 ? ` (+${selectedAlerts.length - 5} more)` : "";
    setCreateActionType("note");
    setCreateActionActor("");
    setCreateActionSummary(`Triage started. Linked ${ids.length} alert(s). Top rule(s): ${ruleNames}${more}.`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showCreate]);

  function toggleSelectAllFiltered(checked: boolean) {
    setSelected((prev) => {
      const next = { ...prev };
      for (const a of filtered) {
        next[a.id] = checked;
      }
      return next;
    });
  }

  async function createIncident() {
    const alertIds = selectedIds;
    if (alertIds.length === 0) return;

    try {
      setCreating(true);
      setErr(null);

      const incident = await api.createIncident({
        title: createTitle.trim() || "Security investigation",
        severity: createSeverity,
        description: createDescription.trim(),
        alert_ids: alertIds,
      });

      const actionSummary = createActionSummary.trim();
      if (actionSummary) {
        await api.createIncidentAction(incident.id, {
          actor: createActionActor.trim() || undefined,
          action_type: createActionType,
          summary: actionSummary,
          details: { alert_ids: alertIds },
        });
      }

      setShowCreate(false);
      setSelected({});
      setNewSinceRefresh(0);
      nav(`/incidents/${incident.id}`);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  }

  async function onDeleteOne(id: string) {
    const ok = window.confirm("Delete this alert?");
    if (!ok) return;

    try {
      setDeletingOne(id);
      setErr(null);
      await api.deleteAlert(id);
      setAlerts((prev) => prev.filter((a) => a.id !== id));
      setSelected((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingOne(null);
    }
  }

  async function onDeleteSelected() {
    const ids = selectedIds;
    if (!ids.length) return;

    const ok = window.confirm(`Delete ${ids.length} selected alert(s)?`);
    if (!ok) return;

    try {
      setDeletingBulk(true);
      setErr(null);

      const results = await Promise.allSettled(ids.map((id) => api.deleteAlert(id)));

      const failed: string[] = [];
      for (let i = 0; i < results.length; i += 1) {
        if (results[i].status === "rejected") failed.push(ids[i]);
      }

      const deletedIds = new Set(ids.filter((id) => !failed.includes(id)));

      setAlerts((prev) => prev.filter((a) => !deletedIds.has(a.id)));

      setSelected((prev) => {
        const next = { ...prev };
        for (const id of deletedIds) delete next[id];
        return next;
      });

      if (failed.length) {
        setErr(`Some deletes failed (${failed.length}). Check your API key and backend routes. Failed ids: ${failed.join(", ")}`);
      }
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingBulk(false);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-slate-900 tracking-tight">Alerts</h1>
          <p className="text-sm text-slate-600">Triage alerts, then group them into incidents with evidence and reports.</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            className="px-3 py-2 rounded-lg text-sm bg-white border border-slate-200 hover:bg-slate-50"
            onClick={() => refreshAlerts(false)}
            type="button"
          >
            Refresh
          </button>

          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Auto-refresh
          </label>

          <select
            className="border border-slate-200 rounded-lg px-3 py-2 text-sm bg-white"
            value={refreshEverySec}
            onChange={(e) => setRefreshEverySec(Number(e.target.value) as (typeof refreshOptionsSec)[number])}
          >
            {refreshOptionsSec.map((s) => (
              <option key={s} value={s}>
                {s}s
              </option>
            ))}
          </select>

          <div className="text-xs text-slate-500">{lastUpdated ? `Updated ${formatTime(lastUpdated)}` : "Not updated yet"}</div>

          <button
            className={`px-4 py-2 rounded-lg text-sm font-medium ${
              selectedIds.length && !deletingBulk
                ? "bg-white border border-rose-200 text-rose-700 hover:bg-rose-50"
                : "bg-slate-200 text-slate-500 cursor-not-allowed"
            }`}
            disabled={!selectedIds.length || deletingBulk}
            onClick={onDeleteSelected}
            type="button"
            title="Delete selected alerts"
          >
            {deletingBulk ? "Deleting..." : "Delete Selected"}
          </button>

          <button
            className={`px-4 py-2 rounded-lg text-sm font-medium ${
              selectedIds.length
                ? "bg-slate-900 text-white hover:bg-slate-800"
                : "bg-slate-200 text-slate-500 cursor-not-allowed"
            }`}
            disabled={!selectedIds.length}
            onClick={() => setShowCreate(true)}
            type="button"
          >
            Create Incident
          </button>
        </div>
      </div>

      {newSinceRefresh > 0 && (
        <div className="bg-emerald-50 border border-emerald-200 text-emerald-900 rounded-xl p-3 text-sm flex items-center justify-between">
          <div>
            <span className="font-semibold">{newSinceRefresh}</span> new alert(s) since last refresh.
          </div>
          <button className="underline" onClick={() => setNewSinceRefresh(0)} type="button">
            Dismiss
          </button>
        </div>
      )}

      <div className="bg-white border border-slate-200 rounded-2xl p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap gap-3 items-center">
          <label className="text-sm font-medium text-slate-700">Severity</label>
          <select
            className="border border-slate-200 rounded-lg px-3 py-2 text-sm bg-white"
            value={severity}
            onChange={(e: ChangeEvent<HTMLSelectElement>) => setSeverity(e.target.value as SeverityFilter)}
          >
            {severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <div className="text-sm text-slate-500">
            Showing <span className="font-medium text-slate-700">{filtered.length}</span> of{" "}
            <span className="font-medium text-slate-700">{alerts.length}</span>
          </div>
        </div>

        <input
          className="border border-slate-200 rounded-lg px-3 py-2 text-sm w-full md:w-[28rem] bg-white"
          placeholder="Search rule, host, user, source..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {loading && (
        <div className="bg-white border border-slate-200 rounded-2xl p-6 text-sm text-slate-600">Loading alerts...</div>
      )}

      {err && <div className="bg-rose-50 border border-rose-200 rounded-2xl p-4 text-sm text-rose-900">{err}</div>}

      {!loading && !err && (
        <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-700">
              <tr>
                <th className="p-3 w-12">
                  <input
                    type="checkbox"
                    checked={allFilteredSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = !allFilteredSelected && someFilteredSelected;
                    }}
                    onChange={(e) => toggleSelectAllFiltered(e.target.checked)}
                  />
                </th>
                <th className="p-3 text-left">Created</th>
                <th className="p-3 text-left">Severity</th>
                <th className="p-3 text-left">Rule</th>
                <th className="p-3 text-left">Host</th>
                <th className="p-3 text-left">User</th>
                <th className="p-3 text-left">Source</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>

            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-600">
                    No alerts match your filters.
                  </td>
                </tr>
              ) : (
                filtered.map((a) => {
                  const isSelected = !!selected[a.id];
                  const isDeleting = deletingOne === a.id;

                  return (
                    <tr
                      key={a.id}
                      className={`border-t ${isSelected ? "bg-slate-50" : "hover:bg-slate-50"}`}
                      onClick={() => setSelected((prev) => ({ ...prev, [a.id]: !prev[a.id] }))}
                      style={{ cursor: "pointer" }}
                    >
                      <td className="p-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => setSelected((prev) => ({ ...prev, [a.id]: e.target.checked }))}
                        />
                      </td>

                      <td className="p-3 text-slate-600 whitespace-nowrap">{new Date(a.created_at).toLocaleString()}</td>

                      <td className="p-3">
                        <span className={`px-2.5 py-1 rounded-full text-xs font-medium inline-flex items-center ${severityPillClass(a.severity)}`}>
                          {a.severity}
                        </span>
                      </td>

                      <td className="p-3">
                        <div className="font-semibold text-slate-900">{a.rule_name}</div>
                        <div className="text-xs text-slate-600">{a.summary}</div>
                      </td>

                      <td className="p-3 text-slate-800">{a.host ?? "n/a"}</td>
                      <td className="p-3 text-slate-800">{a.user ?? "n/a"}</td>
                      <td className="p-3 text-slate-600">{a.source}</td>

                      <td className="p-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex justify-end">
                          <button
                            className={`px-3 py-1.5 rounded-lg text-xs border ${
                              isDeleting
                                ? "bg-slate-100 text-slate-400 border-slate-200 cursor-not-allowed"
                                : "bg-white border-rose-200 text-rose-700 hover:bg-rose-50"
                            }`}
                            onClick={() => onDeleteOne(a.id)}
                            disabled={isDeleting || deletingBulk}
                            type="button"
                          >
                            {isDeleting ? "Deleting..." : "Delete"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-xl p-5 space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-lg font-semibold text-slate-900">Create Incident</div>
                <div className="text-sm text-slate-600">
                  This will link selected alerts, create an initial action (optional), and open the incident view.
                </div>
              </div>

              <button className="text-slate-500 hover:text-slate-900" onClick={() => setShowCreate(false)} type="button">
                Close
              </button>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-sm flex items-center justify-between">
              <div>
                Selected alerts: <span className="font-semibold">{selectedIds.length}</span>
              </div>
              <div className="text-xs text-slate-500">{lastUpdated ? `Latest refresh ${formatTime(lastUpdated)}` : null}</div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="md:col-span-2">
                <label className="text-sm font-medium text-slate-700">Title</label>
                <input className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm" value={createTitle} onChange={(e) => setCreateTitle(e.target.value)} />
              </div>

              <div>
                <label className="text-sm font-medium text-slate-700">Severity</label>
                <select
                  className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm bg-white"
                  value={createSeverity}
                  onChange={(e) => setCreateSeverity(e.target.value as Exclude<SeverityFilter, "all">)}
                >
                  {severities.filter((s) => s !== "all").map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-slate-700">Description</label>
              <textarea className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm min-h-[96px]" value={createDescription} onChange={(e) => setCreateDescription(e.target.value)} />
            </div>

            <div className="border-t pt-4 space-y-3">
              <div className="text-sm font-semibold text-slate-900">Initial Action (optional)</div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="md:col-span-2">
                  <label className="text-sm font-medium text-slate-700">Actor</label>
                  <input
                    className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm"
                    value={createActionActor}
                    onChange={(e) => setCreateActionActor(e.target.value)}
                    placeholder="Justin, SOC Analyst, etc."
                  />
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-700">Type</label>
                  <select
                    className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm bg-white"
                    value={createActionType}
                    onChange={(e) => setCreateActionType(e.target.value as IncidentActionType)}
                  >
                    {actionTypes.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-sm font-medium text-slate-700">Summary</label>
                <textarea
                  className="mt-1 w-full border border-slate-200 rounded-lg px-3 py-2 text-sm min-h-[84px]"
                  value={createActionSummary}
                  onChange={(e) => setCreateActionSummary(e.target.value)}
                  placeholder="What happened, what you did, and what you plan to do next."
                />
                <div className="text-xs text-slate-500 mt-1">Leave blank if you do not want an initial action logged.</div>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <button className="px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200" onClick={() => setShowCreate(false)} type="button">
                Cancel
              </button>

              <button
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  creating ? "bg-slate-300 text-slate-600 cursor-not-allowed" : "bg-slate-900 text-white hover:bg-slate-800"
                }`}
                onClick={createIncident}
                disabled={creating}
                type="button"
              >
                {creating ? "Creating..." : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
