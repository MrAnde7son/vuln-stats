"""
vuln-stats  – FastAPI backend
Serves metrics, triggers ingestion, and streams live data.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import BackgroundTasks, Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, init_db
from ingestion import run_full_ingest
from models import IngestLog, Vulnerability

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    # Kick off initial ingest if DB is empty
    async with __import__("database").AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar()
    if count == 0:
        log.info("Empty DB – scheduling immediate ingest")
        asyncio.create_task(run_full_ingest())

    # Daily re-ingest at 03:00 UTC
    scheduler.add_job(run_full_ingest, "cron", hour=3, minute=0, id="daily_ingest")
    scheduler.start()

    yield

    scheduler.shutdown()


app = FastAPI(title="vuln-stats", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic response models ──────────────────────────────────────────────────
class SummaryStats(BaseModel):
    total_cves: int
    kev_cves: int
    avg_mttr_days: Optional[float]
    avg_mtte_days: Optional[float]
    avg_exposure_window_days: Optional[float]
    median_mttr_days: Optional[float]
    pct_exploited_before_patch: Optional[float]


class DomainBreakdown(BaseModel):
    domain: str
    count: int
    avg_mttr_days: Optional[float]
    avg_mtte_days: Optional[float]
    kev_count: int


class TrendPoint(BaseModel):
    period: str  # "YYYY-MM"
    avg_mttr: Optional[float]
    avg_mtte: Optional[float]
    avg_exposure: Optional[float]
    cve_count: int


class CveDetail(BaseModel):
    cve_id: str
    description: Optional[str]
    published_date: Optional[date]
    fixed_date: Optional[date]
    exploited_date: Optional[date]
    cvss_score: Optional[float]
    epss_score: Optional[float]
    domain: Optional[str]
    mttr_days: Optional[float]
    mtte_days: Optional[float]
    exposure_window_days: Optional[float]
    in_kev: int


# ── Helper ────────────────────────────────────────────────────────────────────
def _round(val):
    return round(val, 1) if val is not None else None


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/summary", response_model=SummaryStats)
async def get_summary(
    domain: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Vulnerability)
    if domain:
        q = q.where(Vulnerability.domain == domain)

    result = await db.execute(q)
    rows = result.scalars().all()

    total = len(rows)
    kev = sum(1 for r in rows if r.in_kev)
    mttrs = [r.mttr_days for r in rows if r.mttr_days is not None]
    mttes = [r.mtte_days for r in rows if r.mtte_days is not None]
    exposures = [r.exposure_window_days for r in rows if r.exposure_window_days is not None]

    exploited_before = sum(
        1
        for r in rows
        if r.mtte_days is not None
        and r.mttr_days is not None
        and r.mtte_days < r.mttr_days
    )

    sorted_mttrs = sorted(mttrs)
    n = len(sorted_mttrs)
    median_mttr = (
        sorted_mttrs[n // 2]
        if n % 2 == 1
        else (sorted_mttrs[n // 2 - 1] + sorted_mttrs[n // 2]) / 2
        if n > 0
        else None
    )

    return SummaryStats(
        total_cves=total,
        kev_cves=kev,
        avg_mttr_days=_round(sum(mttrs) / len(mttrs)) if mttrs else None,
        avg_mtte_days=_round(sum(mttes) / len(mttes)) if mttes else None,
        avg_exposure_window_days=_round(sum(exposures) / len(exposures)) if exposures else None,
        median_mttr_days=_round(median_mttr),
        pct_exploited_before_patch=_round(
            exploited_before / max(len(mttes), 1) * 100
        ) if mttes else None,
    )


@app.get("/api/domains", response_model=list[DomainBreakdown])
async def get_domains(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability))
    rows = result.scalars().all()

    by_domain: dict[str, list] = {}
    for r in rows:
        by_domain.setdefault(r.domain or "other", []).append(r)

    out = []
    for domain, items in sorted(by_domain.items()):
        mttrs = [i.mttr_days for i in items if i.mttr_days is not None]
        mttes = [i.mtte_days for i in items if i.mtte_days is not None]
        out.append(
            DomainBreakdown(
                domain=domain,
                count=len(items),
                avg_mttr_days=_round(sum(mttrs) / len(mttrs)) if mttrs else None,
                avg_mtte_days=_round(sum(mttes) / len(mttes)) if mttes else None,
                kev_count=sum(1 for i in items if i.in_kev),
            )
        )
    return out


@app.get("/api/trends", response_model=list[TrendPoint])
async def get_trends(
    months: int = Query(24, ge=1, le=120),
    domain: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    cutoff = date.today() - timedelta(days=months * 30)
    q = select(Vulnerability).where(Vulnerability.published_date >= cutoff)
    if domain:
        q = q.where(Vulnerability.domain == domain)

    result = await db.execute(q)
    rows = result.scalars().all()

    buckets: dict[str, list] = {}
    for r in rows:
        if r.published_date:
            key = r.published_date.strftime("%Y-%m")
            buckets.setdefault(key, []).append(r)

    out = []
    for period in sorted(buckets):
        items = buckets[period]
        mttrs = [i.mttr_days for i in items if i.mttr_days is not None]
        mttes = [i.mtte_days for i in items if i.mtte_days is not None]
        exposures = [i.exposure_window_days for i in items if i.exposure_window_days is not None]
        out.append(
            TrendPoint(
                period=period,
                avg_mttr=_round(sum(mttrs) / len(mttrs)) if mttrs else None,
                avg_mtte=_round(sum(mttes) / len(mttes)) if mttes else None,
                avg_exposure=_round(sum(exposures) / len(exposures)) if exposures else None,
                cve_count=len(items),
            )
        )
    return out


@app.get("/api/cves", response_model=list[CveDetail])
async def list_cves(
    domain: Optional[str] = None,
    kev_only: bool = False,
    min_cvss: Optional[float] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(Vulnerability).order_by(Vulnerability.published_date.desc())
    if domain:
        q = q.where(Vulnerability.domain == domain)
    if kev_only:
        q = q.where(Vulnerability.in_kev == 1)
    if min_cvss is not None:
        q = q.where(Vulnerability.cvss_score >= min_cvss)
    q = q.limit(limit).offset(offset)

    result = await db.execute(q)
    return [
        CveDetail(
            cve_id=r.cve_id,
            description=r.description,
            published_date=r.published_date,
            fixed_date=r.fixed_date,
            exploited_date=r.exploited_date,
            cvss_score=r.cvss_score,
            epss_score=r.epss_score,
            domain=r.domain,
            mttr_days=r.mttr_days,
            mtte_days=r.mtte_days,
            exposure_window_days=r.exposure_window_days,
            in_kev=r.in_kev,
        )
        for r in result.scalars().all()
    ]


@app.get("/api/cves/{cve_id}", response_model=CveDetail)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper())
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return CveDetail(
        cve_id=vuln.cve_id,
        description=vuln.description,
        published_date=vuln.published_date,
        fixed_date=vuln.fixed_date,
        exploited_date=vuln.exploited_date,
        cvss_score=vuln.cvss_score,
        epss_score=vuln.epss_score,
        domain=vuln.domain,
        mttr_days=vuln.mttr_days,
        mtte_days=vuln.mtte_days,
        exposure_window_days=vuln.exposure_window_days,
        in_kev=vuln.in_kev,
    )


@app.get("/api/epss/distribution")
async def epss_distribution(db: AsyncSession = Depends(get_db)):
    """Histogram of EPSS scores in 10 buckets."""
    result = await db.execute(
        select(Vulnerability.epss_score).where(Vulnerability.epss_score.isnot(None))
    )
    scores = [r[0] for r in result.fetchall()]
    buckets = [0] * 10
    for s in scores:
        idx = min(int(s * 10), 9)
        buckets[idx] += 1
    labels = [f"{i/10:.1f}–{(i+1)/10:.1f}" for i in range(10)]
    return {"labels": labels, "counts": buckets}


@app.get("/api/ingest/status")
async def ingest_status(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(IngestLog).order_by(IngestLog.ran_at.desc()).limit(20)
    )
    rows = result.scalars().all()
    return [
        {
            "source": r.source,
            "status": r.status,
            "records": r.records_processed,
            "message": r.message,
            "ran_at": r.ran_at.isoformat() if r.ran_at else None,
        }
        for r in rows
    ]


@app.post("/api/ingest/trigger")
async def trigger_ingest(background_tasks: BackgroundTasks):
    """Manually kick off a full ingest cycle."""
    background_tasks.add_task(run_full_ingest)
    return {"message": "Ingest triggered"}


# ── Serve frontend ────────────────────────────────────────────────────────────
# Support both "python backend/main.py" (local) and Docker WORKDIR=/app layouts
_HERE = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.environ.get(
    "FRONTEND_DIR",
    os.path.join(_HERE, "..", "frontend"),
)
FRONTEND_DIR = os.path.abspath(FRONTEND_DIR)

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
