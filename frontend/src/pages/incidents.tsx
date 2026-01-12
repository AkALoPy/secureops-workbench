import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Incident } from "../lib/api";
import { Link } from "react-router-dom";

export function IncidentsPage() {
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        setErr(null);
        const data = await api.listIncidents();
        setItems(data);
      } catch (e: unknown) {
        if (e instanceof Error) {
          setErr(e.message);
        } else {
          setErr(String(e));
        }
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">Incidents</h1>
        <p className="text-sm text-slate-600">Track investigations, evidence, and exportable reports.</p>
      </div>

      {loading && <div className="text-sm text-slate-600">Loading incidents...</div>}
      {err && <div className="text-sm text-red-600">{err}</div>}

      {!loading && !err && (
        <div className="bg-white border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-700">
              <tr>
                <th className="p-3 text-left">Created</th>
                <th className="p-3 text-left">Status</th>
                <th className="p-3 text-left">Severity</th>
                <th className="p-3 text-left">Title</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} className="border-t hover:bg-slate-50">
                  <td className="p-3 text-slate-600">{new Date(i.created_at).toLocaleString()}</td>
                  <td className="p-3">
                    <span className="px-2 py-1 rounded-full text-xs bg-slate-100 text-slate-800">{i.status}</span>
                  </td>
                  <td className="p-3">
                    <span className="px-2 py-1 rounded-full text-xs bg-slate-100 text-slate-800">{i.severity}</span>
                  </td>
                  <td className="p-3">
                    <Link className="font-medium text-slate-900 hover:underline" to={`/incidents/${i.id}`}>
                      {i.title}
                    </Link>
                    <div className="text-xs text-slate-600">{i.description}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
