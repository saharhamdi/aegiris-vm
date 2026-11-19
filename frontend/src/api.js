const BASE = import.meta.env.VITE_API_URL || "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* corps non JSON */
    }
    throw new Error(detail || `Erreur ${res.status}`);
  }
  return res.json();
}

const json = (method, body) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  summary: () => request("/dashboard/summary"),
  vulns: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null));
    return request(`/vulnerabilities?${qs}`);
  },
  updateVuln: (id, body) => request(`/vulnerabilities/${id}`, json("PATCH", body)),
  assets: () => request("/assets"),
  createAsset: (body) => request("/assets", json("POST", body)),
  updateAsset: (id, body) => request(`/assets/${id}`, json("PATCH", body)),
  importScan: (tool, text) =>
    request(`/import/${tool}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: text }),
  enrich: () => request("/enrich", { method: "POST" }),
  scans: () => request("/scans"),
  reportUrl: `${BASE}/report.csv`,
};
