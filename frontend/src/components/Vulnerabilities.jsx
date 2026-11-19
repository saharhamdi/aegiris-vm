import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, Loading, PriorityBadge, STATUS_LABELS, formatDate } from "./common.jsx";

export default function Vulnerabilities({ version, onChange }) {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ q: "", priority: "", status: "", kev: "" });

  useEffect(() => {
    const params = { ...filters, kev: filters.kev === "" ? "" : filters.kev };
    api.vulns(params).then(setRows).catch((e) => setError(e.message));
  }, [filters, version]);

  const update = async (id, body) => {
    try {
      await api.updateVuln(id, body);
      onChange();
    } catch (e) {
      setError(e.message);
    }
  };

  const set = (key) => (e) => setFilters((f) => ({ ...f, [key]: e.target.value }));

  return (
    <Card title="Vulnérabilités">
      <div className="toolbar">
        <input placeholder="Rechercher (CVE, titre, actif)…" value={filters.q} onChange={set("q")} />
        <select value={filters.priority} onChange={set("priority")}>
          <option value="">Toutes priorités</option>
          <option value="Critical">Critique</option>
          <option value="High">Élevée</option>
          <option value="Medium">Moyenne</option>
          <option value="Low">Faible</option>
        </select>
        <select value={filters.status} onChange={set("status")}>
          <option value="">Tous statuts</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={filters.kev} onChange={set("kev")}>
          <option value="">KEV : tous</option>
          <option value="true">Exploitées activement</option>
          <option value="false">Non KEV</option>
        </select>
        <a className="btn ghost" href={api.reportUrl}>
          Export CSV
        </a>
      </div>

      {error && <div className="notice error">{error}</div>}
      {!rows ? (
        <Loading />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Priorité</th>
                <th>Vulnérabilité</th>
                <th>Actif</th>
                <th>CVSS / EPSS</th>
                <th>Détectée</th>
                <th>Échéance</th>
                <th>Statut</th>
                <th>Responsable</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.id} className={v.status === "fixed" ? "dim" : ""}>
                  <td>
                    <PriorityBadge priority={v.priority} /> <b>{v.risk_score}</b>
                  </td>
                  <td>
                    <div className="title">{v.title}</div>
                    <small className="muted">
                      {v.cve || "sans CVE"} · {v.scanner}
                    </small>
                    {v.kev && <span className="kev"> KEV</span>}
                  </td>
                  <td>{v.asset}</td>
                  <td>
                    {v.cvss} / {(v.epss * 100).toFixed(0)} %
                  </td>
                  <td>{formatDate(v.first_seen)}</td>
                  <td className={v.overdue ? "overdue" : ""}>{formatDate(v.due_date)}</td>
                  <td>
                    <select value={v.status} onChange={(e) => update(v.id, { status: e.target.value })}>
                      {Object.entries(STATUS_LABELS).map(([k, label]) => (
                        <option key={k} value={k}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      className="inline"
                      defaultValue={v.assignee || ""}
                      placeholder="—"
                      onBlur={(e) => e.target.value !== (v.assignee || "") && update(v.id, { assignee: e.target.value })}
                    />
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan="8" className="muted center">
                    Aucun résultat.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
