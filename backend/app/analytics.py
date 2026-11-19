"""Calculs du dashboard : KPI, tendances, top risques, indicateurs de conformité."""

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import OPEN_STATUSES, Asset, Vulnerability, utcnow

PRIORITIES = ["Critical", "High", "Medium", "Low"]


def vuln_to_dict(v: Vulnerability, now: datetime | None = None) -> dict:
    now = now or utcnow()
    is_open = v.status in OPEN_STATUSES
    return {
        "id": v.id,
        "asset_id": v.asset_id,
        "asset": v.asset.hostname,
        "asset_criticality": v.asset.criticality,
        "cve": v.cve,
        "title": v.title,
        "description": v.description,
        "severity": v.severity,
        "cvss": v.cvss,
        "epss": round(v.epss, 4),
        "kev": v.kev,
        "risk_score": v.risk_score,
        "priority": v.priority,
        "status": v.status,
        "scanner": v.scanner,
        "assignee": v.assignee,
        "first_seen": v.first_seen.isoformat(),
        "due_date": v.due_date.isoformat() if v.due_date else None,
        "fixed_at": v.fixed_at.isoformat() if v.fixed_at else None,
        "overdue": bool(is_open and v.due_date and v.due_date < now),
        "days_open": (now - v.first_seen).days if is_open else None,
    }


def asset_to_dict(a: Asset) -> dict:
    open_vulns = [v for v in a.vulnerabilities if v.status in OPEN_STATUSES]
    return {
        "id": a.id,
        "hostname": a.hostname,
        "ip": a.ip,
        "asset_type": a.asset_type,
        "criticality": a.criticality,
        "owner": a.owner,
        "environment": a.environment,
        "authorization_ref": a.authorization_ref,
        "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
        "open_vulns": len(open_vulns),
        "max_risk": max((v.risk_score for v in open_vulns), default=0),
    }


def _trend(vulns: list[Vulnerability], now: datetime, weeks: int = 8) -> list[dict]:
    points = []
    for i in range(weeks - 1, -1, -1):
        d = now - timedelta(weeks=i)
        prev = d - timedelta(weeks=1)
        open_at = sum(1 for v in vulns if v.first_seen <= d and (v.fixed_at is None or v.fixed_at > d))
        new = sum(1 for v in vulns if prev < v.first_seen <= d)
        fixed = sum(1 for v in vulns if v.fixed_at and prev < v.fixed_at <= d)
        points.append({"label": d.strftime("%d/%m"), "open": open_at, "new": new, "fixed": fixed})
    return points


def compliance_controls(vulns: list[Vulnerability], assets: list[Asset], now: datetime) -> list[dict]:
    """Indicateurs d'appui aux contrôles de conformité (ne remplacent pas un audit)."""
    open_v = [v for v in vulns if v.status in OPEN_STATUSES]
    hi_open = [v for v in open_v if v.priority in ("Critical", "High")]

    scanned = [a for a in assets if a.last_scanned_at and (now - a.last_scanned_at).days <= 30]
    scan_cov = 100 * len(scanned) / len(assets) if assets else 0

    hi_all = [v for v in vulns if v.priority in ("Critical", "High") and v.status != "accepted"]
    on_time = [
        v
        for v in hi_all
        if (v.status == "fixed" and v.fixed_at and v.due_date and v.fixed_at <= v.due_date)
        or (v.status in OPEN_STATUSES and v.due_date and v.due_date >= now)
    ]
    sla_rate = 100 * len(on_time) / len(hi_all) if hi_all else 100

    crit_overdue = [v for v in open_v if v.priority == "Critical" and v.due_date and v.due_date < now]
    old_hi = [v for v in hi_open if (now - v.first_seen).days > 30]

    def grade(ok: bool, warn: bool) -> str:
        return "ok" if ok else "warn" if warn else "ko"

    return [
        {
            "framework": "ISO/IEC 27001:2022",
            "control": "A.8.8 Gestion des vulnérabilités techniques",
            "metric": f"{scan_cov:.0f} % des actifs scannés ces 30 derniers jours",
            "status": grade(scan_cov >= 90, scan_cov >= 60),
        },
        {
            "framework": "CIS Controls v8",
            "control": "7 Gestion continue des vulnérabilités",
            "metric": f"{sla_rate:.0f} % des vulnérabilités Critical/High dans le SLA",
            "status": grade(sla_rate >= 90, sla_rate >= 70),
        },
        {
            "framework": "NIS2",
            "control": "Art. 21(2)(e) Gestion et divulgation des vulnérabilités",
            "metric": f"{len(crit_overdue)} vulnérabilité(s) critique(s) hors SLA",
            "status": grade(len(crit_overdue) == 0, len(crit_overdue) <= 2),
        },
        {
            "framework": "PCI DSS 4.0",
            "control": "6.3.3 Correctifs de sécurité",
            "metric": f"{len(old_hi)} vulnérabilité(s) Critical/High ouvertes depuis plus de 30 jours",
            "status": grade(len(old_hi) == 0, len(old_hi) <= 3),
        },
    ]


def dashboard_summary(db: Session) -> dict:
    now = utcnow()
    vulns = list(db.scalars(select(Vulnerability)))
    assets = list(db.scalars(select(Asset)))
    open_v = [v for v in vulns if v.status in OPEN_STATUSES]

    by_priority = Counter(v.priority for v in open_v)
    by_status = Counter(v.status for v in vulns)
    fixed = [v for v in vulns if v.status == "fixed" and v.fixed_at]
    mttr = round(sum((v.fixed_at - v.first_seen).days for v in fixed) / len(fixed), 1) if fixed else None
    overdue = [v for v in open_v if v.due_date and v.due_date < now]
    risk_index = round(sum(v.risk_score for v in open_v) / len(open_v), 1) if open_v else 0

    top_risks = sorted(open_v, key=lambda v: v.risk_score, reverse=True)[:10]
    top_assets = sorted(
        (asset_to_dict(a) for a in assets), key=lambda a: (a["max_risk"], a["open_vulns"]), reverse=True
    )[:5]

    return {
        "kpis": {
            "assets": len(assets),
            "open": len(open_v),
            "critical_open": by_priority.get("Critical", 0),
            "kev_open": sum(1 for v in open_v if v.kev),
            "overdue": len(overdue),
            "mttr_days": mttr,
            "risk_index": risk_index,
        },
        "by_priority": [{"name": p, "value": by_priority.get(p, 0)} for p in PRIORITIES],
        "by_status": dict(by_status),
        "trend": _trend(vulns, now),
        "top_risks": [vuln_to_dict(v, now) for v in top_risks],
        "top_assets": top_assets,
        "compliance": compliance_controls(vulns, assets, now),
    }
