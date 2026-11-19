import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, formatDate } from "./common.jsx";

const TOOLS = [
  { id: "nuclei", label: "Nuclei", hint: "nuclei -u cible -jsonl -o resultats.jsonl" },
  { id: "trivy", label: "Trivy", hint: "trivy image -f json -o rapport.json mon-image:tag" },
];

export default function ImportPanel({ onChange }) {
  const [tool, setTool] = useState("nuclei");
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [scans, setScans] = useState([]);

  const loadScans = () => api.scans().then(setScans).catch(() => {});
  useEffect(() => {
    loadScans();
  }, []);

  const run = async (fn, okText) => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await fn();
      setMessage({ ok: true, text: okText(result) });
      onChange();
      loadScans();
    } catch (e) {
      setMessage({ ok: false, text: e.message });
    } finally {
      setBusy(false);
    }
  };

  const onFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    run(
      async () => api.importScan(tool, await file.text()),
      (r) => `${r.total} résultats lus : ${r.new} nouveaux, ${r.updated} mis à jour, ${r.reopened} rouverts.`
    );
    e.target.value = "";
  };

  const current = TOOLS.find((t) => t.id === tool);

  return (
    <div className="grid">
      <Card title="Importer un scan" className="span-6">
        <p className="muted">
          Chargez la sortie d'un scanner. Les actifs sont créés automatiquement, les doublons sont fusionnés et le
          score de risque est calculé.
        </p>
        <div className="toolbar">
          <select value={tool} onChange={(e) => setTool(e.target.value)}>
            {TOOLS.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
          <label className="btn">
            Choisir un fichier
            <input type="file" hidden disabled={busy} onChange={onFile} />
          </label>
        </div>
        <code className="hint">{current.hint}</code>
        <p className="warning">
          Ne scannez que des systèmes pour lesquels vous disposez d'une autorisation écrite.
        </p>
      </Card>

      <Card title="Enrichissement (CISA KEV + EPSS)" className="span-6">
        <p className="muted">
          Interroge les sources publiques CISA KEV et FIRST EPSS, puis recalcule les scores et les échéances de
          remédiation. Nécessite un accès Internet.
        </p>
        <button
          className="btn"
          disabled={busy}
          onClick={() =>
            run(api.enrich, (r) => `${r.enriched} vulnérabilités enrichies, dont ${r.kev} présentes dans CISA KEV.`)
          }
        >
          Lancer l'enrichissement
        </button>
      </Card>

      {message && (
        <div className={`notice span-12 ${message.ok ? "success" : "error"}`}>{message.text}</div>
      )}

      <Card title="Historique des imports" className="span-12">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Outil</th>
                <th>Résultats</th>
                <th>Nouveaux</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{formatDate(s.started_at)}</td>
                  <td>{s.tool}</td>
                  <td>{s.total}</td>
                  <td>{s.new_findings}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td colSpan="4" className="muted center">
                    Aucun import pour le moment.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
