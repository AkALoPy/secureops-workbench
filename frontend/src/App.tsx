import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/layout";
import { AlertsPage } from "./pages/alerts";
import { IncidentsPage } from "./pages/incidents";
import { IncidentDetailPage } from "./pages/incident-detail";
import { ImportsPage } from "./pages/imports";

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<AlertsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/imports" element={<ImportsPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
