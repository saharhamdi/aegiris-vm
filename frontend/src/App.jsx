import { useCallback, useState } from "react";
import Dashboard from "./components/Dashboard.jsx";
import Vulnerabilities from "./components/Vulnerabilities.jsx";
import Assets from "./components/Assets.jsx";
import ImportPanel from "./components/ImportPanel.jsx";

const TABS = [
  { id: "dashboard", label: "Tableau de bord" },
  { id: "vulns", label: "Vulnérabilités" },
  { id: "assets", label: "Actifs" },
  { id: "import", label: "Import & enrichissement" },
];

export default function App() {
  const [tab, setTab] = useState("dashboard");
  // Incrémenté après chaque modification pour recharger les vues
  const [version, setVersion] = useState(0);
  const refresh = useCallback(() => setVersion((v) => v + 1), []);

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <img src="/emblem.png" alt="" className="brand-emblem" />
          <div className="brand-text">
            <span className="brand-name">AEGIRIS</span>
            <span className="brand-sub">Vulnerability Management</span>
          </div>
        </div>
        <nav>
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "tab active" : "tab"} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main>
        {tab === "dashboard" && <Dashboard version={version} />}
        {tab === "vulns" && <Vulnerabilities version={version} onChange={refresh} />}
        {tab === "assets" && <Assets version={version} onChange={refresh} />}
        {tab === "import" && <ImportPanel onChange={refresh} />}
      </main>

      <footer>
        <img src="/emblem.png" alt="" className="footer-logo" />
        <span>Aegiris Vulnerability Management · See the risk. Shield the business.</span>
      </footer>
    </div>
  );
}
