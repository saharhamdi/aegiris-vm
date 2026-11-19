import json
from urllib.parse import urlparse


def _hostname(value: str) -> str:
    if not value:
        return "unknown"
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname or value


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def parse_nuclei(text: str, include_info: bool = False) -> list[dict]:
    """Parse la sortie Nuclei (JSONL via `-jsonl`, ou tableau JSON via `-json-export`)."""
    text = (text or "").strip()
    if not text:
        return []

    if text.startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]

    findings = []
    for rec in records:
        info = rec.get("info") or {}
        severity = (info.get("severity") or "unknown").lower()
        if severity == "info" and not include_info:
            continue

        classification = info.get("classification") or {}
        cve = _first(classification.get("cve-id"))
        cvss = classification.get("cvss-score")

        host = _hostname(rec.get("host") or rec.get("matched-at") or rec.get("ip") or "")
        findings.append(
            {
                "host": host,
                "ip": rec.get("ip"),
                "asset_type": "web",
                "title": info.get("name") or rec.get("template-id") or "Nuclei finding",
                "description": info.get("description"),
                "cve": cve.upper() if isinstance(cve, str) else None,
                "cvss": float(cvss) if cvss not in (None, "") else None,
                "severity": severity,
                "scanner": "nuclei",
            }
        )
    return findings
