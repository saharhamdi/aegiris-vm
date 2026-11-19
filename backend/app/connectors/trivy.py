import json


def _best_cvss(cvss_block: dict | None) -> float | None:
    """Prend le meilleur score CVSS v3 (sinon v2) parmi les sources fournies par Trivy."""
    if not cvss_block:
        return None
    v3 = [s.get("V3Score") for s in cvss_block.values() if s.get("V3Score")]
    if v3:
        return float(max(v3))
    v2 = [s.get("V2Score") for s in cvss_block.values() if s.get("V2Score")]
    return float(max(v2)) if v2 else None


def parse_trivy(text: str) -> list[dict]:
    """Parse un rapport Trivy au format JSON (`trivy image|fs|config -f json`)."""
    text = (text or "").strip()
    if not text:
        return []

    data = json.loads(text)
    artifact = data.get("ArtifactName") or "unknown-artifact"
    asset_type = "container" if data.get("ArtifactType") == "container_image" else "application"

    findings = []
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID") or ""
            pkg = f"{vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '')}".strip()
            title = vuln.get("Title") or vuln_id or "Vulnérabilité"
            fixed = vuln.get("FixedVersion")
            description = vuln.get("Description") or ""
            if fixed:
                description = f"{description}\nCorrectif : {fixed}".strip()
            findings.append(
                {
                    "host": artifact,
                    "ip": None,
                    "asset_type": asset_type,
                    "title": f"{pkg} : {title}",
                    "description": description or None,
                    "cve": vuln_id.upper() if vuln_id.upper().startswith("CVE-") else None,
                    "cvss": _best_cvss(vuln.get("CVSS")),
                    "severity": (vuln.get("Severity") or "unknown").lower(),
                    "scanner": "trivy",
                }
            )
    return findings
