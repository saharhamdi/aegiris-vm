"""Données de démonstration 100 % fictives (cibles de lab : DVWA, Juice Shop, Metasploitable...).

Les CVE sont réelles et publiques ; les valeurs EPSS sont indicatives (démo) et sont
remplacées par les vraies valeurs via POST /api/enrich.
"""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset, Vulnerability, utcnow
from .scoring import due_date_for, priority_from_score, risk_score

ASSETS = [
    # hostname, ip, type, criticité, environnement, propriétaire
    ("dvwa-lab", "10.10.10.21", "web", 2, "lab", "Équipe sécurité"),
    ("juice-shop", "10.10.10.22", "web", 3, "lab", "Équipe sécurité"),
    ("metasploitable-2", "10.10.10.30", "server", 2, "lab", "Équipe sécurité"),
    ("dc01.demo.local", "10.10.20.5", "server", 5, "prod", "Infrastructure"),
    ("app-prod-01", "10.10.20.14", "server", 4, "prod", "Applications"),
    ("db-prod-01", "10.10.20.20", "server", 5, "prod", "Infrastructure"),
    ("demo/api:1.4.2", None, "container", 3, "prod", "DevOps"),
    ("vpn-gw", "10.10.1.2", "network", 4, "prod", "Réseau"),
    ("win-ws-014", "10.10.30.14", "workstation", 1, "prod", "Support"),
    ("mail-01", "10.10.20.30", "server", 4, "prod", "Infrastructure"),
]

# asset, cve, titre, sévérité, cvss, epss, kev, scanner, jours depuis détection, statut
FINDINGS = [
    ("app-prod-01", "CVE-2021-44228", "Apache Log4j2 : exécution de code à distance (Log4Shell)", "critical", 10.0, 0.97, True, "openvas", 38, "in_progress"),
    ("demo/api:1.4.2", "CVE-2022-22965", "Spring Framework : RCE via data binding (Spring4Shell)", "critical", 9.8, 0.97, True, "trivy", 21, "open"),
    ("dc01.demo.local", "CVE-2020-1472", "Netlogon : élévation de privilèges (Zerologon)", "critical", 10.0, 0.96, True, "openvas", 52, "open"),
    ("metasploitable-2", "CVE-2017-0144", "SMBv1 : exécution de code à distance (EternalBlue)", "high", 8.1, 0.97, True, "openvas", 44, "open"),
    ("win-ws-014", "CVE-2019-0708", "RDP : exécution de code à distance (BlueKeep)", "critical", 9.8, 0.97, True, "openvas", 15, "open"),
    ("vpn-gw", "CVE-2014-0160", "OpenSSL : fuite mémoire (Heartbleed)", "high", 7.5, 0.94, True, "openvas", 60, "open"),
    ("app-prod-01", "CVE-2021-41773", "Apache HTTP Server 2.4.49 : traversée de chemin", "high", 7.5, 0.97, True, "nuclei", 9, "open"),
    ("demo/api:1.4.2", "CVE-2023-4863", "libwebp : débordement de tampon heap", "high", 8.8, 0.83, True, "trivy", 12, "open"),
    ("mail-01", "CVE-2018-15473", "OpenSSH : énumération d'utilisateurs", "medium", 5.3, 0.65, False, "openvas", 70, "open"),
    ("db-prod-01", "CVE-2016-2183", "TLS : chiffrement 3DES vulnérable (Sweet32)", "high", 7.5, 0.1, False, "openvas", 30, "in_progress"),
    ("vpn-gw", "CVE-2016-2183", "TLS : chiffrement 3DES vulnérable (Sweet32)", "high", 7.5, 0.1, False, "openvas", 28, "open"),
    ("dvwa-lab", None, "Identifiants par défaut sur l'interface d'administration", "high", 8.0, 0.0, False, "nuclei", 5, "open"),
    ("dvwa-lab", None, "Injection SQL sur le formulaire de connexion", "critical", 9.0, 0.0, False, "zap", 5, "open"),
    ("juice-shop", None, "Listage de répertoires activé", "medium", 5.3, 0.0, False, "nuclei", 20, "open"),
    ("juice-shop", None, "En-tête HSTS manquant", "low", 3.1, 0.0, False, "zap", 20, "open"),
    ("juice-shop", None, "jQuery obsolète (< 3.5) avec vulnérabilités XSS connues", "medium", 6.1, 0.0, False, "nuclei", 33, "accepted"),
    ("app-prod-01", None, "TLS 1.0/1.1 activé", "medium", 5.9, 0.0, False, "openvas", 90, "open"),
    ("db-prod-01", None, "Port de base de données exposé sur le sous-réseau utilisateurs", "high", 7.0, 0.0, False, "nmap", 18, "open"),
    ("mail-01", None, "Relais SMTP ouvert", "high", 7.5, 0.0, False, "openvas", 14, "fixed"),
    ("dc01.demo.local", "CVE-2021-34527", "Windows Print Spooler : exécution de code (PrintNightmare)", "high", 8.8, 0.97, True, "openvas", 75, "fixed"),
    ("win-ws-014", "CVE-2017-11882", "Microsoft Office : corruption mémoire (Equation Editor)", "high", 7.8, 0.97, True, "openvas", 55, "fixed"),
    ("vpn-gw", None, "Certificat TLS expirant sous 30 jours", "low", 2.0, 0.0, False, "nuclei", 8, "open"),
    ("metasploitable-2", None, "Service Telnet activé", "medium", 6.5, 0.0, False, "nmap", 44, "open"),
]


def seed_demo(db: Session) -> bool:
    """Insère les données de démo si la base est vide. Retourne True si inséré."""
    if db.scalar(select(Asset.id).limit(1)) is not None:
        return False

    now = utcnow()
    assets: dict[str, Asset] = {}
    for hostname, ip, atype, crit, env, owner in ASSETS:
        asset = Asset(
            hostname=hostname,
            ip=ip,
            asset_type=atype,
            criticality=crit,
            environment=env,
            owner=owner,
            authorization_ref="DEMO-LAB-001 (données fictives)",
            last_scanned_at=now - timedelta(days=2),
        )
        db.add(asset)
        assets[hostname] = asset
    db.flush()

    for host, cve, title, sev, cvss, epss, kev, scanner, days, status in FINDINGS:
        asset = assets[host]
        first_seen = now - timedelta(days=days)
        score = risk_score(cvss, epss, kev, asset.criticality)
        priority = priority_from_score(score)
        due = due_date_for(priority, first_seen)
        fixed_at = None
        if status == "fixed":
            fixed_at = first_seen + timedelta(days=max(2, int(days * 0.45)))
        fp = f"{host}|{cve}" if cve else f"{host}|{scanner}|{title}"
        db.add(
            Vulnerability(
                asset_id=asset.id,
                fingerprint=fp,
                cve=cve,
                title=title,
                severity=sev,
                cvss=cvss,
                epss=epss,
                kev=kev,
                risk_score=score,
                priority=priority,
                status=status,
                scanner=scanner,
                assignee="Équipe " + asset.owner.split()[-1] if status == "in_progress" else None,
                first_seen=first_seen,
                last_seen=now - timedelta(days=1) if status != "fixed" else fixed_at,
                fixed_at=fixed_at,
                due_date=due,
            )
        )
    db.commit()
    return True
