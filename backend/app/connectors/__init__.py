from .nuclei import parse_nuclei
from .trivy import parse_trivy

# Chaque parser transforme la sortie brute d'un scanner en liste de findings normalisés :
# {host, ip, asset_type, title, description, cve, cvss, severity, scanner}
PARSERS = {
    "nuclei": parse_nuclei,
    "trivy": parse_trivy,
}

__all__ = ["PARSERS", "parse_nuclei", "parse_trivy"]
