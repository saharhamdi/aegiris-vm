// Palette Aegiris : marine, or, bleu acier, sur fond crème.
// Les couleurs de priorité restent sémantiques (rouge → bleu) mais accordées à la charte.
export const PRIORITY_COLORS = {
  Critical: "#b42318",
  High: "#d9822b",
  Medium: "#c59b45",
  Low: "#4f76a8",
};

export const CHART = {
  navy: "#0a2543",
  steel: "#38567c",
  gold: "#c59b45",
  grid: "#e6e0d2",
  axis: "#5b6b86",
};

export const PRIORITY_LABELS = {
  Critical: "Critique",
  High: "Élevée",
  Medium: "Moyenne",
  Low: "Faible",
};

export const STATUS_LABELS = {
  open: "Ouverte",
  in_progress: "En cours",
  fixed: "Corrigée",
  accepted: "Risque accepté",
};

export function PriorityBadge({ priority }) {
  return (
    <span className="badge" style={{ "--c": PRIORITY_COLORS[priority] || "#5b6b86" }}>
      {PRIORITY_LABELS[priority] || priority}
    </span>
  );
}

export function Card({ title, children, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {title && <h2>{title}</h2>}
      {children}
    </section>
  );
}

export function Loading({ error }) {
  if (error) return <div className="notice error">Erreur : {error}</div>;
  return <div className="notice">Chargement…</div>;
}

export const formatDate = (iso) => (iso ? new Date(iso).toLocaleDateString("fr-FR") : "—");
