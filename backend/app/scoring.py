"""Moteur de scoring de risque.

Le score combine quatre signaux gratuits et publics :
  - CVSS (gravité technique)           : poids principal
  - EPSS (probabilité d'exploitation)  : bonus proportionnel
  - CISA KEV (exploitée activement)    : bonus fixe important
  - Criticité de l'actif (1..5)        : multiplicateur métier

Le résultat est borné à 0..100 et converti en priorité (Critical/High/Medium/Low),
qui détermine le SLA de remédiation.
"""

from datetime import datetime, timedelta

CRITICALITY_MULTIPLIER = {1: 0.8, 2: 0.9, 3: 1.0, 4: 1.15, 5: 1.3}
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}
SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
    "unknown": 5.0,
}

CVSS_WEIGHT = 7.0  # cvss (0..10) * 7 => 0..70
EPSS_WEIGHT = 20.0  # epss (0..1) * 20 => 0..20
KEV_BONUS = 25.0


def severity_to_cvss(severity: str) -> float:
    return SEVERITY_TO_CVSS.get((severity or "unknown").lower(), 5.0)


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def risk_score(cvss: float, epss: float, kev: bool, criticality: int) -> float:
    base = max(0.0, min(10.0, cvss or 0.0)) * CVSS_WEIGHT
    epss_part = max(0.0, min(1.0, epss or 0.0)) * EPSS_WEIGHT
    kev_part = KEV_BONUS if kev else 0.0
    multiplier = CRITICALITY_MULTIPLIER.get(int(criticality or 3), 1.0)
    return round(min(100.0, (base + epss_part + kev_part) * multiplier), 1)


def priority_from_score(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def due_date_for(priority: str, first_seen: datetime) -> datetime:
    return first_seen + timedelta(days=SLA_DAYS.get(priority, 90))
