import pytest

from app.connectors import parse_nuclei, parse_trivy


def test_nuclei_parses_and_skips_info(nuclei_sample):
    findings = parse_nuclei(nuclei_sample)
    assert len(findings) == 3  # la ligne "info" est ignorée
    cve = next(f for f in findings if f["cve"])
    assert cve["cve"] == "CVE-2021-41773"
    assert cve["host"] == "demo-web.local"
    assert cve["cvss"] == 7.5


def test_nuclei_can_include_info(nuclei_sample):
    assert len(parse_nuclei(nuclei_sample, include_info=True)) == 4


def test_nuclei_empty_input():
    assert parse_nuclei("") == []


def test_trivy_parses_container(trivy_sample):
    findings = parse_trivy(trivy_sample)
    assert len(findings) == 3
    assert all(f["host"] == "demo/api:1.4.2" for f in findings)
    assert all(f["asset_type"] == "container" for f in findings)
    spring = next(f for f in findings if f["cve"] == "CVE-2022-22965")
    assert spring["cvss"] == 9.8
    # Les identifiants GHSA ne sont pas des CVE
    assert any(f["cve"] is None for f in findings)


def test_trivy_invalid_json():
    with pytest.raises(ValueError):
        parse_trivy("not json")
