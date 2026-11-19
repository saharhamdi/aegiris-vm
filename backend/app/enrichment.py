"""Enrichissement via des sources publiques et gratuites : CISA KEV et FIRST EPSS."""

import json
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_HEADERS = {"User-Agent": "AegirisVM/0.1 (+vulnerability-management)"}


def _get_json(url: str, timeout: int = 25) -> dict:
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URLs constantes)
        return json.loads(resp.read().decode("utf-8"))


def fetch_kev() -> set[str]:
    data = _get_json(KEV_URL)
    return {item["cveID"].upper() for item in data.get("vulnerabilities", [])}


def fetch_epss(cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    unique = sorted(set(c.upper() for c in cves))
    for i in range(0, len(unique), 100):
        batch = unique[i : i + 100]
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(batch)})}"
        for row in _get_json(url).get("data", []):
            scores[row["cve"].upper()] = float(row["epss"])
    return scores
