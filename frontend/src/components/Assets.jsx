import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Card, Loading, formatDate } from "./common.jsx";

const EMPTY = { hostname: "", ip: "", asset_type: "server", criticality: 3, environment: "prod", owner: "", authorization_ref: "" };

export default function Assets({ version, onChange }) {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  const [form, setForm] = useState(EMPTY);

  useEffect(() => {
    api.assets().then(setRows).catch((e) => setError(e.message));
  }, [version]);

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      await api.createAsset({ ...form, criticality: Number(form.criticality), ip: form.ip || null, owner: form.owner || null, authorization_ref: form.authorization_ref || null });
      setForm(EMPTY);
      onChange();
    } catch (err) {
      setError(err.message);
    }
  };

  const setCriticality = async (id, value) => {
    try {
      await api.updateAsset(id, { criticality: Number(value) });
      onChange();
    } catch (err) {
      setError(err.message);
    }
  };

  const field = (key) => ({ value: form[key], onChange: (e) => setForm((f) => ({ ...f, [key]: e.target.value })) });

  return (
    <div className="grid">
      <Card title="Inventaire des actifs" className="span-8">
        {error && <div className="notice error">{error}</div>}
        {!rows ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Actif</th>
                  <th>Type</th>
                  <th>Environnement</th>
                  <th>Criticité</th>
                  <th>Vuln. ouvertes</th>
                  <th>Dernier scan</th>
                  <th>Autorisation de scan</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div className="title">{a.hostname}</div>
                      <small className="muted">{a.ip || "—"}</small>
                    </td>
                    <td>{a.asset_type}</td>
                    <td>{a.environment}</td>
                    <td>
                      <select value={a.criticality} onChange={(e) => setCriticality(a.id, e.target.value)}>
                        {[1, 2, 3, 4, 5].map((n) => (
                          <option key={n} value={n}>
                            {n}/5
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>{a.open_vulns}</td>
                    <td>{formatDate(a.last_scanned_at)}</td>
                    <td>{a.authorization_ref || <span className="overdue">non renseignée</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Ajouter un actif" className="span-4">
        <form className="form" onSubmit={submit}>
          <label>
            Nom d'hôte / identifiant
            <input required {...field("hostname")} />
          </label>
          <label>
            Adresse IP
            <input {...field("ip")} />
          </label>
          <label>
            Type
            <select {...field("asset_type")}>
              {["server", "web", "container", "network", "workstation", "application"].map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label>
            Criticité métier (1-5)
            <select {...field("criticality")}>
              {[1, 2, 3, 4, 5].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <label>
            Environnement
            <select {...field("environment")}>
              {["prod", "preprod", "dev", "lab"].map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label>
            Propriétaire
            <input {...field("owner")} />
          </label>
          <label>
            Référence d'autorisation de scan
            <input placeholder="ex. contrat / ticket / RoE" {...field("authorization_ref")} />
          </label>
          <button className="btn" type="submit">
            Ajouter
          </button>
        </form>
      </Card>
    </div>
  );
}
