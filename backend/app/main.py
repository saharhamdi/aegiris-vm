import csv
import io
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import analytics, enrichment, ingest, seed
from .connectors import PARSERS
from .database import Base, SessionLocal, engine, get_db
from .models import ALL_STATUSES, Asset, Scan, Vulnerability, utcnow


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    if os.getenv("SEED_DEMO", "false").lower() == "true":
        with SessionLocal() as db:
            seed.seed_demo(db)
    yield


app = FastAPI(title="Aegiris Vulnerability Management", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


class AssetIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip: str | None = None
    asset_type: str = "host"
    criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = None
    environment: str = "prod"
    authorization_ref: str | None = None


class AssetUpdate(BaseModel):
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = None
    environment: str | None = None
    authorization_ref: str | None = None


class VulnUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/dashboard/summary")
def dashboard(db: Session = Depends(get_db)):
    return analytics.dashboard_summary(db)


@app.get("/api/assets")
def list_assets(db: Session = Depends(get_db)):
    return [analytics.asset_to_dict(a) for a in db.scalars(select(Asset).order_by(Asset.hostname))]


@app.post("/api/assets", status_code=201)
def create_asset(payload: AssetIn, db: Session = Depends(get_db)):
    if db.scalar(select(Asset).where(Asset.hostname == payload.hostname)):
        raise HTTPException(409, "Un actif avec ce nom existe déjà")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return analytics.asset_to_dict(asset)


@app.patch("/api/assets/{asset_id}")
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Actif introuvable")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, key, value)
    # Un changement de criticité modifie le risque de toutes ses vulnérabilités.
    for vuln in asset.vulnerabilities:
        ingest.rescore(vuln)
    db.commit()
    return analytics.asset_to_dict(asset)


@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    status: str | None = None,
    priority: str | None = None,
    asset_id: int | None = None,
    kev: bool | None = None,
    q: str | None = Query(default=None, description="Recherche CVE / titre / actif"),
    db: Session = Depends(get_db),
):
    stmt = select(Vulnerability).join(Asset).order_by(Vulnerability.risk_score.desc())
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if priority:
        stmt = stmt.where(Vulnerability.priority == priority)
    if asset_id:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev == kev)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            Vulnerability.title.ilike(like) | Vulnerability.cve.ilike(like) | Asset.hostname.ilike(like)
        )
    now = utcnow()
    return [analytics.vuln_to_dict(v, now) for v in db.scalars(stmt)]


@app.patch("/api/vulnerabilities/{vuln_id}")
def update_vulnerability(vuln_id: int, payload: VulnUpdate, db: Session = Depends(get_db)):
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(404, "Vulnérabilité introuvable")
    if payload.status is not None:
        if payload.status not in ALL_STATUSES:
            raise HTTPException(422, f"Statut invalide. Valeurs : {', '.join(ALL_STATUSES)}")
        vuln.status = payload.status
        vuln.fixed_at = utcnow() if payload.status == "fixed" else None
    if payload.assignee is not None:
        vuln.assignee = payload.assignee or None
    db.commit()
    return analytics.vuln_to_dict(vuln)


@app.post("/api/import/{tool}")
async def import_scan(tool: str, request: Request, target: str = "", db: Session = Depends(get_db)):
    """Importe la sortie brute d'un scanner (corps de la requête = contenu du fichier)."""
    parser = PARSERS.get(tool)
    if parser is None:
        raise HTTPException(404, f"Connecteur inconnu. Disponibles : {', '.join(PARSERS)}")
    raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        findings = parser(raw)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, f"Fichier {tool} invalide : {exc}") from exc
    return ingest.ingest_findings(db, tool, findings, target)


@app.post("/api/enrich")
def enrich(db: Session = Depends(get_db)):
    """Enrichit les vulnérabilités avec CISA KEV et EPSS (nécessite un accès Internet)."""
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.cve.is_not(None))))
    if not vulns:
        return {"enriched": 0, "kev": 0}
    try:
        kev_set = enrichment.fetch_kev()
        epss = enrichment.fetch_epss([v.cve for v in vulns])
    except Exception as exc:  # réseau, quota, format inattendu
        raise HTTPException(502, f"Sources d'enrichissement indisponibles : {exc}") from exc

    kev_count = 0
    for v in vulns:
        v.kev = v.cve.upper() in kev_set
        v.epss = epss.get(v.cve.upper(), v.epss)
        kev_count += int(v.kev)
        ingest.rescore(v)
    db.commit()
    return {"enriched": len(vulns), "kev": kev_count}


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    rows = db.scalars(select(Scan).order_by(Scan.started_at.desc()).limit(50))
    return [
        {
            "id": s.id,
            "tool": s.tool,
            "target": s.target,
            "started_at": s.started_at.isoformat(),
            "total": s.total,
            "new_findings": s.new_findings,
        }
        for s in rows
    ]


@app.get("/api/report.csv")
def report_csv(db: Session = Depends(get_db)):
    now = utcnow()
    rows = [
        analytics.vuln_to_dict(v, now)
        for v in db.scalars(select(Vulnerability).order_by(Vulnerability.risk_score.desc()))
    ]
    columns = [
        "asset", "cve", "title", "priority", "risk_score", "cvss", "epss", "kev",
        "status", "assignee", "first_seen", "due_date", "overdue",
    ]  # fmt: skip
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegiris-vm-report.csv"},
    )
