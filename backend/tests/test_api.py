from app import seed
from app.database import SessionLocal


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_import_nuclei_creates_assets_and_vulns(client, nuclei_sample):
    r = client.post("/api/import/nuclei", content=nuclei_sample)
    assert r.status_code == 200
    assert r.json()["new"] == 3

    vulns = client.get("/api/vulnerabilities").json()
    assert len(vulns) == 3
    assert vulns[0]["cve"] == "CVE-2021-41773"  # trié par risque décroissant
    assert client.get("/api/assets").json()[0]["hostname"] == "demo-web.local"


def test_reimport_is_deduplicated(client, nuclei_sample):
    client.post("/api/import/nuclei", content=nuclei_sample)
    second = client.post("/api/import/nuclei", content=nuclei_sample).json()
    assert second["new"] == 0
    assert second["updated"] == 3
    assert len(client.get("/api/vulnerabilities").json()) == 3


def test_same_cve_from_two_scanners_is_one_vulnerability(client, trivy_sample):
    client.post("/api/import/trivy", content=trivy_sample)
    again = client.post("/api/import/trivy", content=trivy_sample).json()
    assert again["new"] == 0


def test_unknown_connector(client):
    assert client.post("/api/import/foo", content="x").status_code == 404


def test_invalid_file_returns_422(client):
    assert client.post("/api/import/trivy", content="not json").status_code == 422


def test_status_workflow_and_reopen(client, nuclei_sample):
    client.post("/api/import/nuclei", content=nuclei_sample)
    vuln = client.get("/api/vulnerabilities").json()[0]

    fixed = client.patch(f"/api/vulnerabilities/{vuln['id']}", json={"status": "fixed"}).json()
    assert fixed["status"] == "fixed" and fixed["fixed_at"]

    # Un nouveau scan qui revoit la vulnérabilité la rouvre
    again = client.post("/api/import/nuclei", content=nuclei_sample).json()
    assert again["reopened"] == 1
    reopened = client.get("/api/vulnerabilities?status=open").json()
    assert any(v["id"] == vuln["id"] for v in reopened)


def test_invalid_status_rejected(client, nuclei_sample):
    client.post("/api/import/nuclei", content=nuclei_sample)
    vid = client.get("/api/vulnerabilities").json()[0]["id"]
    assert client.patch(f"/api/vulnerabilities/{vid}", json={"status": "nope"}).status_code == 422


def test_asset_criticality_change_rescores(client, nuclei_sample):
    client.post("/api/import/nuclei", content=nuclei_sample)
    asset = client.get("/api/assets").json()[0]
    before = client.get("/api/vulnerabilities").json()[0]["risk_score"]
    client.patch(f"/api/assets/{asset['id']}", json={"criticality": 5})
    after = client.get("/api/vulnerabilities").json()[0]["risk_score"]
    assert after > before


def test_create_asset_and_conflict(client):
    payload = {"hostname": "srv-test", "criticality": 4}
    assert client.post("/api/assets", json=payload).status_code == 201
    assert client.post("/api/assets", json=payload).status_code == 409
    assert client.post("/api/assets", json={"hostname": "x", "criticality": 9}).status_code == 422


def test_dashboard_with_demo_data(client):
    with SessionLocal() as db:
        assert seed.seed_demo(db) is True
        assert seed.seed_demo(db) is False  # idempotent

    summary = client.get("/api/dashboard/summary").json()
    kpis = summary["kpis"]
    assert kpis["assets"] == 10
    assert kpis["open"] > 0
    assert kpis["kev_open"] > 0
    assert len(summary["by_priority"]) == 4
    assert len(summary["trend"]) == 8
    assert len(summary["compliance"]) == 4
    scores = [v["risk_score"] for v in summary["top_risks"]]
    assert scores == sorted(scores, reverse=True)


def test_csv_report(client, nuclei_sample):
    client.post("/api/import/nuclei", content=nuclei_sample)
    r = client.get("/api/report.csv")
    assert r.status_code == 200
    assert r.text.splitlines()[0].startswith("asset,cve,title")
    assert "CVE-2021-41773" in r.text
