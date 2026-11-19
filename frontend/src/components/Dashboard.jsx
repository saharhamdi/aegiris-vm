import { useEffect, useState } from "react";
import {
  Area,
  Bar,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api.js";
import { CHART, Card, Loading, PRIORITY_COLORS, PRIORITY_LABELS, PriorityBadge, formatDate } from "./common.jsx";

const tooltipStyle = {
  background: "#ffffff",
  border: `1px solid ${CHART.grid}`,
  borderRadius: 8,
  color: CHART.navy,
  boxShadow: "0 4px 14px rgba(10,37,67,0.12)",
};

function Kpi({ label, value, hint, tone }) {
  return (
    <div className={`kpi ${tone || ""}`}>
      <span className="kpi-label">{label}</span>
      <strong className="kpi-value">{value}</strong>
      {hint && <span className="kpi-hint">{hint}</span>}
    </div>
  );
}

export default function Dashboard({ version }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.summary().then(setData).catch((e) => setError(e.message));
  }, [version]);

  if (!data) return <Loading error={error} />;
  const { kpis, by_priority, trend, top_risks, top_assets, compliance } = data;
  const pieData = by_priority.filter((p) => p.value > 0).map((p) => ({ key: p.name, name: PRIORITY_LABELS[p.name], value: p.value }));

  return (
    <div className="grid">
      <div className="kpis">
        <Kpi label="Vulnérabilités ouvertes" value={kpis.open} hint={`sur ${kpis.assets} actifs`} />
        <Kpi label="Critiques ouvertes" value={kpis.critical_open} tone="danger" />
        <Kpi label="Exploitées activement (KEV)" value={kpis.kev_open} tone="danger" hint="CISA KEV" />
        <Kpi label="Hors SLA" value={kpis.overdue} tone={kpis.overdue ? "warn" : ""} />
        <Kpi label="Délai moyen de correction" value={kpis.mttr_days == null ? "—" : `${kpis.mttr_days} j`} />
        <Kpi label="Indice de risque" value={`${kpis.risk_index}/100`} hint="moyenne des vulnérabilités ouvertes" />
      </div>

      <Card title="Répartition par priorité" className="span-4">
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3} stroke="none" isAnimationActive={false}>
              {pieData.map((p) => (
                <Cell key={p.key} fill={PRIORITY_COLORS[p.key]} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </Card>

      <Card title="Tendance sur 8 semaines" className="span-8">
        <ResponsiveContainer width="100%" height={250}>
          <ComposedChart data={trend}>
            <CartesianGrid stroke={CHART.grid} vertical={false} />
            <XAxis dataKey="label" stroke={CHART.axis} />
            <YAxis stroke={CHART.axis} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend />
            <Area isAnimationActive={false} type="monotone" dataKey="open" name="Ouvertes" stroke={CHART.navy} strokeWidth={2} fill="#0a254322" />
            <Bar isAnimationActive={false} dataKey="new" name="Nouvelles" fill={CHART.gold} radius={[3, 3, 0, 0]} />
            <Bar isAnimationActive={false} dataKey="fixed" name="Corrigées" fill={CHART.steel} radius={[3, 3, 0, 0]} />
          </ComposedChart>
        </ResponsiveContainer>
      </Card>

      <Card title="Top 10 des risques à traiter en premier" className="span-8">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Vulnérabilité</th>
                <th>Actif</th>
                <th>Signaux</th>
                <th>Échéance</th>
              </tr>
            </thead>
            <tbody>
              {top_risks.map((v) => (
                <tr key={v.id}>
                  <td>
                    <PriorityBadge priority={v.priority} /> <b>{v.risk_score}</b>
                  </td>
                  <td>
                    <div className="title">{v.title}</div>
                    <small className="muted">{v.cve || "—"}</small>
                  </td>
                  <td>{v.asset}</td>
                  <td>
                    <div className="signals">
                    <span title="CVSS">CVSS {v.cvss}</span>
                    <span title="Probabilité d'exploitation">EPSS {(v.epss * 100).toFixed(0)} %</span>
                    {v.kev && <span className="kev">KEV</span>}
                    </div>
                  </td>
                  <td className={v.overdue ? "overdue" : ""}>{formatDate(v.due_date)}</td>
                </tr>
              ))}
              {top_risks.length === 0 && (
                <tr>
                  <td colSpan="5" className="muted center">
                    Aucune vulnérabilité ouverte. Importez un scan ou chargez les données de démo.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="span-4 stack">
        <Card title="Actifs les plus exposés">
          <ul className="asset-list">
            {top_assets.map((a) => (
              <li key={a.id}>
                <div>
                  <b>{a.hostname}</b>
                  <small className="muted"> criticité {a.criticality}/5</small>
                </div>
                <div className="bar">
                  <i style={{ width: `${a.max_risk}%` }} />
                </div>
                <small className="muted">
                  {a.open_vulns} ouverte(s) · risque max {a.max_risk}
                </small>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Appui à la conformité">
          <ul className="compliance">
            {compliance.map((c) => (
              <li key={c.control}>
                <span className={`dot ${c.status}`} />
                <div>
                  <b>{c.framework}</b> — {c.control}
                  <small className="muted">{c.metric}</small>
                </div>
              </li>
            ))}
          </ul>
          <small className="muted">Indicateurs d'appui, ils ne remplacent pas un audit de conformité.</small>
        </Card>
      </div>
    </div>
  );
}
