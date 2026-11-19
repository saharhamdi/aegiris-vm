"""Import de findings normalisés : création des actifs, déduplication, scoring, SLA."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset, Scan, Vulnerability, utcnow
from .scoring import due_date_for, priority_from_score, risk_score, severity_to_cvss


def fingerprint(finding: dict) -> str:
    # Une même CVE vue par deux scanners sur le même actif = une seule vulnérabilité.
    if finding.get("cve"):
        return f"{finding['host']}|{finding['cve']}"
    return f"{finding['host']}|{finding['scanner']}|{finding['title']}"


def ingest_findings(db: Session, tool: str, findings: list[dict], target: str = "") -> dict:
    now = utcnow()
    stats = {"total": len(findings), "new": 0, "updated": 0, "reopened": 0}
    asset_cache: dict[str, Asset] = {}

    for f in findings:
        host = f["host"]
        asset = asset_cache.get(host) or db.scalar(select(Asset).where(Asset.hostname == host))
        if asset is None:
            asset = Asset(
                hostname=host,
                ip=f.get("ip"),
                asset_type=f.get("asset_type", "host"),
                criticality=3,
            )
            db.add(asset)
            db.flush()
        asset.last_scanned_at = now
        asset_cache[host] = asset

        fp = fingerprint(f)
        vuln = db.scalar(select(Vulnerability).where(Vulnerability.fingerprint == fp))
        if vuln is not None:
            vuln.last_seen = now
            if vuln.status == "fixed":
                vuln.status = "open"
                vuln.fixed_at = None
                stats["reopened"] += 1
            else:
                stats["updated"] += 1
            continue

        cvss = f["cvss"] if f.get("cvss") is not None else severity_to_cvss(f["severity"])
        score = risk_score(cvss, 0.0, False, asset.criticality)
        priority = priority_from_score(score)
        db.add(
            Vulnerability(
                asset_id=asset.id,
                fingerprint=fp,
                cve=f.get("cve"),
                title=f["title"][:512],
                description=f.get("description"),
                severity=f["severity"],
                cvss=cvss,
                risk_score=score,
                priority=priority,
                scanner=f["scanner"],
                first_seen=now,
                last_seen=now,
                due_date=due_date_for(priority, now),
            )
        )
        stats["new"] += 1

    db.add(Scan(tool=tool, target=target, started_at=now, total=stats["total"], new_findings=stats["new"]))
    db.commit()
    return stats


def rescore(vuln: Vulnerability) -> None:
    """Recalcule score, priorité et échéance (après enrichissement ou changement de criticité)."""
    vuln.risk_score = risk_score(vuln.cvss, vuln.epss, vuln.kev, vuln.asset.criticality)
    vuln.priority = priority_from_score(vuln.risk_score)
    vuln.due_date = due_date_for(vuln.priority, vuln.first_seen)
