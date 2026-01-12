import { NavLink } from "react-router-dom";


function linkClass({ isActive }: { isActive: boolean }) {
  return `px-3 py-2 rounded-lg text-sm font-medium ${
    isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
  }`;
}

export function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50">
      <header className="border-b bg-white">
        <div className="mx-auto max-w-6xl px-4 py-4 flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-slate-900">SecureOps Workbench</div>
            <div className="text-xs text-slate-500">Alerts, Incidents, Evidence, Reporting</div>
          </div>
          <nav className="flex gap-2">
            <NavLink to="/" className={linkClass} end>
              Alerts
            </NavLink>
            <NavLink to="/incidents" className={linkClass}>
              Incidents
            </NavLink>
            <NavLink to="/imports" className={linkClass}>
              Imports
            </NavLink>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
    </div>
  );
}
