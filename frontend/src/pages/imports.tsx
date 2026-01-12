import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { ImportJob, Rule } from "../lib/api";

function badgeClass() {
  return "inline-flex items-center rounded-full bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700";
}

function severityBadgeClass(sev: string) {
  switch (sev) {
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

function truncateMiddle(value: string, left = 10, right = 10) {
  if (!value) return value;
  if (value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(value.length - right)}`;
}

const ruleSeverities = ["low", "medium", "high", "critical"] as const;

export function ImportsPage() {
  const [items, setItems] = useState<ImportJob[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);

  const [loading, setLoading] = useState(true);
  const [loadingRules, setLoadingRules] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("linux-auth");
  const [host, setHost] = useState("");
  const [user, setUser] = useState("");

  const [uploading, setUploading] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  // Admin API key
  const [adminKey, setAdminKey] = useState(() => localStorage.getItem("admin_api_key") ?? "");
  const [savingKey, setSavingKey] = useState(false);

  // AWS CloudTrail sync
  const [awsMinutes, setAwsMinutes] = useState(60);
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [syncingAws, setSyncingAws] = useState(false);

  // Import deletion
  const [deletingImportId, setDeletingImportId] = useState<string | null>(null);

  // Rule builder state
  const [ruleName, setRuleName] = useState("Suspicious keyword match");
  const [ruleSeverity, setRuleSeverity] = useState<(typeof ruleSeverities)[number]>("medium");
  const [ruleMatchSource, setRuleMatchSource] = useState("*");
  const [ruleMatchField, setRuleMatchField] = useState("message");
  const [ruleMatchContains, setRuleMatchContains] = useState("failed");
  const [ruleDescription, setRuleDescription] = useState("");
  const [creatingRule, setCreatingRule] = useState(false);

  async function refreshImports() {
    try {
      setLoading(true);
      setErr(null);
      const data = await api.listImports();
      setItems(data);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function refreshRules() {
    try {
      setLoadingRules(true);
      setErr(null);
      const data = await api.listRules();
      setRules(data);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingRules(false);
    }
  }

  useEffect(() => {
    void refreshImports();
    void refreshRules();
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  const canUpload = useMemo(() => {
    return !!file && source.trim().length > 0 && !uploading;
  }, [file, source, uploading]);

  const canCreateRule = useMemo(() => {
    return (
      ruleName.trim().length > 0 &&
      ruleMatchSource.trim().length > 0 &&
      ruleMatchField.trim().length > 0 &&
      ruleMatchContains.trim().length > 0 &&
      !creatingRule
    );
  }, [ruleName, ruleMatchSource, ruleMatchField, ruleMatchContains, creatingRule]);

  async function onUpload() {
    if (!file) return;

    try {
      setUploading(true);
      setErr(null);

      const job = await api.importJsonl(file, {
        source: source.trim(),
        host: host.trim() || undefined,
        user: user.trim() || undefined,
      });

      setToast(`Imported ${job.events_ingested} event(s) from ${job.filename} into source "${job.source}".`);

      setFile(null);
      setHost("");
      setUser("");

      await refreshImports();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setUploading(false);
    }
  }

  async function onCreateRule() {
    try {
      setCreatingRule(true);
      setErr(null);

      const created = await api.createRule({
        name: ruleName.trim(),
        severity: ruleSeverity,
        description: ruleDescription.trim(),
        match_source: ruleMatchSource.trim(),
        match_field: ruleMatchField.trim(),
        match_contains: ruleMatchContains.trim(),
      });

      setToast(`Rule created: "${created.name}" (${created.severity}).`);
      await refreshRules();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setCreatingRule(false);
    }
  }

  async function onDeleteImport(id: string) {
    const ok = window.confirm("Delete this import job record? This removes the job record, it may not remove ingested events.");
    if (!ok) return;

    try {
      setDeletingImportId(id);
      setErr(null);
      await api.deleteImportJob(id);
      setToast("Import job deleted.");
      await refreshImports();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingImportId(null);
    }
  }

  async function onSaveAdminKey() {
    try {
      setSavingKey(true);
      setErr(null);

      const trimmed = adminKey.trim();
      if (!trimmed) {
        localStorage.removeItem("admin_api_key");
        setToast("Admin API key cleared.");
        return;
      }

      localStorage.setItem("admin_api_key", trimmed);
      setToast("Admin API key saved.");
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingKey(false);
    }
  }

  async function onAwsSync() {
    try {
      setSyncingAws(true);
      setErr(null);

      const minutes = Number.isFinite(awsMinutes) ? awsMinutes : 60;
      const region = awsRegion.trim() || "us-east-1";

      const res = await api.syncAwsCloudTrail({ minutes, region });
      setToast(`CloudTrail sync complete, ingested ${res.events_ingested} event(s), region=${res.region}.`);
      await refreshImports();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncingAws(false);
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Imports</h1>
          <p className="text-sm text-slate-600">
            Bulk-ingest JSONL logs into Events, then run detections to produce Alerts. Manage detection rules here.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            className="px-4 py-2 rounded-lg text-sm bg-white border hover:bg-slate-50"
            onClick={() => {
              void refreshImports();
              void refreshRules();
            }}
            disabled={loading || loadingRules}
            title="Refresh imports and rules"
          >
            Refresh
          </button>

          <button
            className="px-4 py-2 rounded-lg text-sm bg-slate-900 text-white hover:bg-slate-800"
            onClick={async () => {
              try {
                setErr(null);
                const res = await api.runDetections();
                setToast(`Detections ran, alerts_created=${res.alerts_created}.`);
              } catch (e: unknown) {
                setErr(e instanceof Error ? e.message : String(e));
              }
            }}
            title="Run detections against latest events"
          >
            Run detections
          </button>
        </div>
      </div>

      {toast ? (
        <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-xl px-4 py-3 text-sm">
          {toast}
        </div>
      ) : null}

      {err ? (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl px-4 py-3 text-sm">
          {err}
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left column */}
        <div className="space-y-4">
          {/* Admin key */}
          <div className="bg-white border rounded-2xl p-4 space-y-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">Admin</div>
              <div className="text-xs text-slate-600 mt-1">
                Some endpoints require an <span className="font-mono">X-API-Key</span>. This is stored in{" "}
                <span className="font-mono">localStorage.admin_api_key</span>.
              </div>
            </div>

            <label className="block">
              <div className="text-xs font-medium text-slate-700 mb-1">Admin API key</div>
              <input
                className="w-full border rounded-lg px-3 py-2 text-sm font-mono"
                value={adminKey}
                onChange={(e) => setAdminKey(e.target.value)}
                placeholder="paste key here"
              />
            </label>

            <div className="flex justify-end gap-2">
              <button
                className="px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200"
                onClick={() => setAdminKey("")}
                disabled={savingKey}
                type="button"
              >
                Clear
              </button>
              <button
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  savingKey ? "bg-slate-300 text-slate-600 cursor-not-allowed" : "bg-slate-900 text-white hover:bg-slate-800"
                }`}
                onClick={onSaveAdminKey}
                disabled={savingKey}
                type="button"
              >
                {savingKey ? "Saving..." : "Save"}
              </button>
            </div>
          </div>

          {/* AWS sync */}
          <div className="bg-white border rounded-2xl p-4 space-y-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">AWS CloudTrail</div>
              <div className="text-xs text-slate-600 mt-1">
                Pull recent CloudTrail events into your Events table using the AWS connector.
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3">
              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Region</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={awsRegion}
                  onChange={(e) => setAwsRegion(e.target.value)}
                  placeholder="us-east-1"
                />
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Lookback minutes</div>
                <input
                  type="number"
                  min={1}
                  max={1440}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={awsMinutes}
                  onChange={(e) => setAwsMinutes(Number(e.target.value))}
                />
              </label>
            </div>

            <div className="flex justify-end">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  syncingAws ? "bg-slate-300 text-slate-600 cursor-not-allowed" : "bg-slate-900 text-white hover:bg-slate-800"
                }`}
                onClick={onAwsSync}
                disabled={syncingAws}
                type="button"
              >
                {syncingAws ? "Syncing..." : "Sync CloudTrail"}
              </button>
            </div>

            <div className="text-xs text-slate-500">
              Tip: After sync, click <span className="font-medium">Run detections</span> to generate Alerts from CloudTrail events.
            </div>
          </div>

          {/* Upload JSONL */}
          <div className="bg-white border rounded-2xl p-4 space-y-4">
            <div>
              <div className="text-sm font-semibold text-slate-900">Upload JSONL</div>
              <div className="text-xs text-slate-600 mt-1">
                One JSON object per line. Each line becomes an Event.raw object.
              </div>
            </div>

            <div className="space-y-3">
              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Source (required)</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="linux-auth"
                />
              </label>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-1 gap-3">
                <label className="block">
                  <div className="text-xs font-medium text-slate-700 mb-1">Host (optional)</div>
                  <input
                    className="w-full border rounded-lg px-3 py-2 text-sm"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="lab-ubuntu"
                  />
                </label>

                <label className="block">
                  <div className="text-xs font-medium text-slate-700 mb-1">User (optional)</div>
                  <input
                    className="w-full border rounded-lg px-3 py-2 text-sm"
                    value={user}
                    onChange={(e) => setUser(e.target.value)}
                    placeholder="root"
                  />
                </label>
              </div>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">File</div>
                <input
                  type="file"
                  accept=".jsonl,.log,.txt,application/json,text/plain"
                  className="block w-full text-sm"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                {file ? (
                  <div className="text-xs text-slate-600 mt-1">
                    Selected: <span className="font-medium text-slate-900">{file.name}</span>{" "}
                    <span className={badgeClass()}>{Math.round(file.size / 1024)} KB</span>
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 mt-1">No file selected.</div>
                )}
              </label>
            </div>

            <div className="flex justify-end gap-2">
              <button
                className="px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200"
                onClick={() => {
                  setFile(null);
                  setHost("");
                  setUser("");
                }}
                disabled={uploading}
              >
                Clear
              </button>

              <button
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  canUpload
                    ? "bg-slate-900 text-white hover:bg-slate-800"
                    : "bg-slate-200 text-slate-500 cursor-not-allowed"
                }`}
                onClick={onUpload}
                disabled={!canUpload}
              >
                {uploading ? "Uploading..." : "Upload"}
              </button>
            </div>

            <div className="text-xs text-slate-500">
              Tip: After upload, click <span className="font-medium">Run detections</span> to generate Alerts.
            </div>
          </div>

          {/* Rules */}
          <div className="bg-white border rounded-2xl p-4 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-slate-900">Detection Rules</div>
                <div className="text-xs text-slate-600 mt-1">
                  Rules are evaluated against Event.raw using <span className="font-mono">match_field</span> (dot path supported).
                </div>
              </div>
              <button
                className="px-3 py-2 rounded-lg text-xs bg-white border border-slate-200 hover:bg-slate-50"
                onClick={() => refreshRules()}
                disabled={loadingRules}
              >
                Refresh rules
              </button>
            </div>

            <div className="space-y-3">
              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Name</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="Suspicious keyword match"
                />
              </label>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="block">
                  <div className="text-xs font-medium text-slate-700 mb-1">Severity</div>
                  <select
                    className="w-full border rounded-lg px-3 py-2 text-sm bg-white"
                    value={ruleSeverity}
                    onChange={(e) => setRuleSeverity(e.target.value as (typeof ruleSeverities)[number])}
                  >
                    {ruleSeverities.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="block">
                  <div className="text-xs font-medium text-slate-700 mb-1">
                    Match source
                    <button
                      type="button"
                      className="ml-2 text-xs underline text-slate-600 hover:text-slate-900"
                      onClick={() => setRuleMatchSource(source.trim() || "*")}
                      title="Set to current upload Source value"
                    >
                      use upload source
                    </button>
                  </div>
                  <input
                    className="w-full border rounded-lg px-3 py-2 text-sm"
                    value={ruleMatchSource}
                    onChange={(e) => setRuleMatchSource(e.target.value)}
                    placeholder='linux-auth or "*"'
                  />
                </label>
              </div>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Match field (dot path)</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm font-mono"
                  value={ruleMatchField}
                  onChange={(e) => setRuleMatchField(e.target.value)}
                  placeholder="event.action or message"
                />
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Match contains</div>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm font-mono"
                  value={ruleMatchContains}
                  onChange={(e) => setRuleMatchContains(e.target.value)}
                  placeholder="failed password"
                />
              </label>

              <label className="block">
                <div className="text-xs font-medium text-slate-700 mb-1">Description (optional)</div>
                <textarea
                  className="w-full border rounded-lg px-3 py-2 text-sm min-h-[72px]"
                  value={ruleDescription}
                  onChange={(e) => setRuleDescription(e.target.value)}
                  placeholder="What this rule detects and why it matters."
                />
              </label>

              <div className="flex justify-end">
                <button
                  className={`px-4 py-2 rounded-lg text-sm font-medium ${
                    canCreateRule
                      ? "bg-slate-900 text-white hover:bg-slate-800"
                      : "bg-slate-200 text-slate-500 cursor-not-allowed"
                  }`}
                  onClick={onCreateRule}
                  disabled={!canCreateRule}
                >
                  {creatingRule ? "Creating..." : "Create rule"}
                </button>
              </div>
            </div>

            <div className="border-t pt-3">
              <div className="text-xs text-slate-600 mb-2">
                Existing rules: <span className="font-medium text-slate-900">{rules.length}</span>
              </div>

              {loadingRules ? (
                <div className="text-sm text-slate-600">Loading rules...</div>
              ) : rules.length === 0 ? (
                <div className="text-sm text-slate-600">No rules yet. Create one above.</div>
              ) : (
                <div className="space-y-2 max-h-[240px] overflow-auto pr-1">
                  {rules.map((r) => (
                    <div key={r.id} className="border border-slate-200 rounded-xl p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-semibold text-slate-900">{r.name}</div>
                          <div className="text-xs text-slate-600 mt-1">
                            <span className={`px-2 py-0.5 rounded-full text-[11px] border ${severityBadgeClass(r.severity)}`}>
                              {r.severity}
                            </span>
                            <span className="mx-2 text-slate-300">|</span>
                            <span className="font-mono text-[11px] text-slate-700">{r.match_source}</span>
                            <span className="mx-2 text-slate-300">|</span>
                            <span className="font-mono text-[11px] text-slate-700">{r.match_field}</span>
                          </div>
                        </div>

                        <div className="font-mono text-[11px] text-slate-600 text-right">
                          {truncateMiddle(r.id, 8, 8)}
                        </div>
                      </div>

                      <div className="mt-2 text-xs text-slate-700">
                        contains: <span className="font-mono">{JSON.stringify(r.match_contains)}</span>
                      </div>

                      {r.description ? <div className="mt-2 text-xs text-slate-600">{r.description}</div> : null}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="text-xs text-slate-500">
              Tip: Import logs, then run detections. If you get no alerts, your match_field likely does not exist in Event.raw.
            </div>
          </div>
        </div>

        {/* Right column: Imports table */}
        <div className="bg-white border rounded-2xl overflow-hidden lg:col-span-2">
          <div className="p-4 border-b flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-slate-900">Recent import jobs</div>
              <div className="text-xs text-slate-600">Jobs recorded by the backend (GET /imports).</div>
            </div>

            <div className="text-xs text-slate-500">
              Showing <span className="font-medium text-slate-900">{items.length}</span>
            </div>
          </div>

          {loading ? (
            <div className="p-4 text-sm text-slate-600">Loading imports...</div>
          ) : items.length === 0 ? (
            <div className="p-4 text-sm text-slate-600">No import jobs yet.</div>
          ) : (
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-slate-700">
                  <tr>
                    <th className="p-3 text-left">Created</th>
                    <th className="p-3 text-left">Source</th>
                    <th className="p-3 text-left">File</th>
                    <th className="p-3 text-left">Events</th>
                    <th className="p-3 text-left">SHA-256</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((j) => (
                    <tr key={j.id} className="border-t hover:bg-slate-50">
                      <td className="p-3 text-slate-600">
                        {j.created_at ? new Date(j.created_at).toLocaleString() : "n/a"}
                      </td>
                      <td className="p-3">
                        <span className={badgeClass()}>{j.source}</span>
                        {j.host || j.user ? (
                          <div className="text-xs text-slate-600 mt-1">
                            {j.host ? (
                              <>
                                Host: <span className="font-medium">{j.host}</span>
                              </>
                            ) : null}
                            {j.host && j.user ? <span> • </span> : null}
                            {j.user ? (
                              <>
                                User: <span className="font-medium">{j.user}</span>
                              </>
                            ) : null}
                          </div>
                        ) : null}
                      </td>
                      <td className="p-3">
                        <div className="font-medium text-slate-900">{j.filename}</div>
                        <div className="text-xs text-slate-600">Job ID: {truncateMiddle(j.id, 8, 8)}</div>
                      </td>
                      <td className="p-3">
                        <span className={badgeClass()}>{j.events_ingested}</span>
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-600">{truncateMiddle(j.sha256, 12, 12)}</td>
                      <td className="p-3">
                        <div className="flex justify-end">
                          <button
                            className={`px-3 py-1.5 rounded-lg text-xs border ${
                              deletingImportId === j.id
                                ? "bg-slate-100 text-slate-400 border-slate-200 cursor-not-allowed"
                                : "bg-white border-rose-200 text-rose-700 hover:bg-rose-50"
                            }`}
                            onClick={() => onDeleteImport(j.id)}
                            disabled={deletingImportId === j.id}
                            type="button"
                          >
                            {deletingImportId === j.id ? "Deleting..." : "Delete"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
