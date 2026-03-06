"""
Data ingestion engine pulling from:
  - CISA KEV  (exploit sighting dates)
  - NVD API 2.0  (disclosure dates, CVSS, CPE, CWE)
  - OSV.dev  (fix dates for open-source packages)
  - EPSS API  (exploit probability scores)
"""

import asyncio
import logging
from datetime import date, datetime, timedelta
from typing import Optional

import httpx
from dateutil.parser import parse as parse_date
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_upsert
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from models import IngestLog, Vulnerability

log = logging.getLogger(__name__)

# ── API endpoints ──────────────────────────────────────────────────────────────
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss"

# ── Domain classification ──────────────────────────────────────────────────────
CPE_DOMAIN_MAP = {
    "os": [
        "cpe:2.3:o:microsoft:windows",
        "cpe:2.3:o:linux:linux_kernel",
        "cpe:2.3:o:apple:macos",
        "cpe:2.3:o:apple:mac_os_x",
        "cpe:2.3:o:canonical:ubuntu",
        "cpe:2.3:o:redhat:enterprise_linux",
        "cpe:2.3:o:debian:debian_linux",
        "cpe:2.3:o:freebsd",
        "cpe:2.3:o:sun:solaris",
    ],
    "cloud": [
        "cpe:2.3:a:amazon:aws",
        "cpe:2.3:a:amazon:ec2",
        "cpe:2.3:a:google:cloud",
        "cpe:2.3:a:microsoft:azure",
        "cpe:2.3:a:kubernetes",
        "cpe:2.3:a:docker",
        "cpe:2.3:a:hashicorp",
    ],
    "saas": [
        "cpe:2.3:a:salesforce",
        "cpe:2.3:a:atlassian:jira",
        "cpe:2.3:a:atlassian:confluence",
        "cpe:2.3:a:servicenow",
        "cpe:2.3:a:workday",
        "cpe:2.3:a:zoom",
        "cpe:2.3:a:slack",
    ],
    "webapp": [
        "cpe:2.3:a:apache:http_server",
        "cpe:2.3:a:nginx",
        "cpe:2.3:a:wordpress",
        "cpe:2.3:a:drupal",
        "cpe:2.3:a:joomla",
        "cpe:2.3:a:php",
    ],
}
WEBAPP_CWES = {"CWE-89", "CWE-79", "CWE-352", "CWE-22", "CWE-94"}


def classify_domain(cpe_str: str, cwe_ids: str) -> str:
    cpe_lower = (cpe_str or "").lower()
    cwes = set((cwe_ids or "").split(","))

    for domain, prefixes in CPE_DOMAIN_MAP.items():
        if any(p.lower() in cpe_lower for p in prefixes):
            return domain

    if cwes & WEBAPP_CWES:
        return "webapp"

    return "other"


def safe_date(val) -> Optional[date]:
    if not val:
        return None
    try:
        if isinstance(val, date):
            return val
        return parse_date(str(val)).date()
    except Exception:
        return None


def calc_days(start: Optional[date], end: Optional[date]) -> Optional[float]:
    if start and end and end >= start:
        return float((end - start).days)
    return None


# ── CISA KEV ──────────────────────────────────────────────────────────────────
async def ingest_cisa_kev(client: httpx.AsyncClient, db: AsyncSession):
    log.info("Fetching CISA KEV…")
    resp = await client.get(CISA_KEV_URL, timeout=60)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])

    upsert_data = []
    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        exploited_date = safe_date(v.get("dateAdded"))
        upsert_data.append(
            {
                "cve_id": cve_id,
                "exploited_date": exploited_date,
                "in_kev": 1,
                "updated_at": datetime.utcnow(),
            }
        )

    if upsert_data:
        stmt = sqlite_upsert(Vulnerability).values(upsert_data)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "exploited_date": stmt.excluded.exploited_date,
                "in_kev": stmt.excluded.in_kev,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        await db.execute(stmt)
        await db.commit()

    log.info("CISA KEV: upserted %d records", len(upsert_data))
    return len(upsert_data)


# ── NVD API 2.0 ───────────────────────────────────────────────────────────────
async def ingest_nvd(
    client: httpx.AsyncClient,
    db: AsyncSession,
    days_back: int = 120,
    max_pages: int = 10,
):
    """Fetch recent CVEs from NVD and upsert into DB."""
    log.info("Fetching NVD CVEs (last %d days)…", days_back)

    pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

    start_index = 0
    results_per_page = 2000
    total_processed = 0

    for _ in range(max_pages):
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        resp = await client.get(NVD_CVE_URL, params=params, timeout=90)
        resp.raise_for_status()
        data = resp.json()

        items = data.get("vulnerabilities", [])
        if not items:
            break

        upsert_data = []
        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            published = safe_date(cve.get("published"))
            description = next(
                (
                    d["value"]
                    for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                None,
            )

            # CVSS score (prefer v3.1 > v3.0 > v2)
            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            # CPE strings
            cpe_parts = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        uri = match.get("criteria", "")
                        if uri:
                            cpe_parts.append(uri)
            cpe_str = " ".join(cpe_parts)

            # CWE IDs
            cwe_ids = ",".join(
                w.get("value", "")
                for w in cve.get("weaknesses", [{}])[0].get("description", [])
                if w.get("value", "").startswith("CWE-")
            )

            domain = classify_domain(cpe_str, cwe_ids)

            upsert_data.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": published,
                    "cvss_score": cvss_score,
                    "cpe_data": cpe_str[:4000] if cpe_str else None,
                    "cwe_ids": cwe_ids or None,
                    "domain": domain,
                    "updated_at": datetime.utcnow(),
                }
            )

        if upsert_data:
            stmt = sqlite_upsert(Vulnerability).values(upsert_data)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "description": stmt.excluded.description,
                    "published_date": stmt.excluded.published_date,
                    "cvss_score": stmt.excluded.cvss_score,
                    "cpe_data": stmt.excluded.cpe_data,
                    "cwe_ids": stmt.excluded.cwe_ids,
                    "domain": stmt.excluded.domain,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            await db.execute(stmt)
            await db.commit()

        total_processed += len(items)
        total_results = data.get("totalResults", 0)
        start_index += results_per_page

        if start_index >= total_results:
            break

        await asyncio.sleep(6)  # NVD rate limit: ~10 req/min without API key

    log.info("NVD: processed %d CVEs", total_processed)
    return total_processed


# ── OSV.dev (fix dates) ───────────────────────────────────────────────────────
async def enrich_fixed_dates(client: httpx.AsyncClient, db: AsyncSession, batch: int = 50):
    """Query OSV for CVEs that have no fixed_date yet."""
    result = await db.execute(
        select(Vulnerability.cve_id).where(Vulnerability.fixed_date.is_(None)).limit(batch)
    )
    cve_ids = [r[0] for r in result.fetchall()]

    updated = 0
    for cve_id in cve_ids:
        try:
            resp = await client.post(
                OSV_QUERY_URL,
                json={"package": {}, "query": cve_id},
                timeout=30,
            )
            if resp.status_code != 200:
                continue
            osvs = resp.json().get("vulns", [])
            fixed_date = None
            for osv in osvs:
                for alias in osv.get("aliases", []):
                    if alias == cve_id:
                        for affected in osv.get("affected", []):
                            for rng in affected.get("ranges", []):
                                for event in rng.get("events", []):
                                    if "fixed" in event:
                                        fixed_date = safe_date(
                                            osv.get("modified") or osv.get("published")
                                        )
            if fixed_date:
                result2 = await db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                )
                vuln = result2.scalar_one_or_none()
                if vuln:
                    vuln.fixed_date = fixed_date
                    _recalc(vuln)
                    updated += 1
        except Exception as exc:
            log.warning("OSV lookup failed for %s: %s", cve_id, exc)
        await asyncio.sleep(0.2)

    await db.commit()
    log.info("OSV: enriched %d fix dates", updated)
    return updated


# ── EPSS scores ───────────────────────────────────────────────────────────────
async def enrich_epss(client: httpx.AsyncClient, db: AsyncSession, batch: int = 100):
    """Bulk-fetch current EPSS scores for CVEs missing them."""
    result = await db.execute(
        select(Vulnerability.cve_id).where(Vulnerability.epss_score.is_(None)).limit(batch)
    )
    cve_ids = [r[0] for r in result.fetchall()]
    if not cve_ids:
        return 0

    cve_param = ",".join(cve_ids)
    try:
        resp = await client.get(
            EPSS_URL,
            params={"cve": cve_param},
            timeout=30,
        )
        resp.raise_for_status()
        epss_list = resp.json().get("data", [])
    except Exception as exc:
        log.warning("EPSS fetch failed: %s", exc)
        return 0

    score_map = {e["cve"]: float(e["epss"]) for e in epss_list if "cve" in e and "epss" in e}
    updated = 0
    for cve_id, score in score_map.items():
        result2 = await db.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
        vuln = result2.scalar_one_or_none()
        if vuln:
            vuln.epss_score = score
            updated += 1

    await db.commit()
    log.info("EPSS: updated %d scores", updated)
    return updated


# ── Metric recalculation ──────────────────────────────────────────────────────
def _recalc(vuln: Vulnerability):
    vuln.mttr_days = calc_days(vuln.published_date, vuln.fixed_date)
    vuln.mtte_days = calc_days(vuln.published_date, vuln.exploited_date)
    if vuln.mttr_days is not None and vuln.mtte_days is not None:
        vuln.exposure_window_days = vuln.mttr_days - vuln.mtte_days
    else:
        vuln.exposure_window_days = None


async def recalculate_metrics(db: AsyncSession):
    """Recompute MTTR / MTTE / Exposure Window for every row that has enough data."""
    result = await db.execute(select(Vulnerability))
    vulns = result.scalars().all()
    for v in vulns:
        _recalc(v)
    await db.commit()
    log.info("Metrics recalculated for %d rows", len(vulns))
    return len(vulns)


# ── Full ingest pipeline ───────────────────────────────────────────────────────
async def run_full_ingest():
    log.info("Starting full ingest pipeline…")
    async with AsyncSessionLocal() as db:
        async with httpx.AsyncClient(
            headers={"User-Agent": "vuln-stats-app/1.0"},
            follow_redirects=True,
        ) as client:
            # 1. CISA KEV (exploit dates)
            try:
                kev_count = await ingest_cisa_kev(client, db)
                await _log(db, "cisa_kev", "ok", kev_count)
            except Exception as exc:
                log.error("CISA KEV failed: %s", exc)
                await _log(db, "cisa_kev", "error", 0, str(exc))

            # 2. NVD (disclosure, CVSS, CPE, CWE)
            try:
                nvd_count = await ingest_nvd(client, db, days_back=120)
                await _log(db, "nvd", "ok", nvd_count)
            except Exception as exc:
                log.error("NVD failed: %s", exc)
                await _log(db, "nvd", "error", 0, str(exc))

            # 3. OSV (fix dates)
            try:
                osv_count = await enrich_fixed_dates(client, db)
                await _log(db, "osv", "ok", osv_count)
            except Exception as exc:
                log.error("OSV failed: %s", exc)
                await _log(db, "osv", "error", 0, str(exc))

            # 4. EPSS
            try:
                epss_count = await enrich_epss(client, db)
                await _log(db, "epss", "ok", epss_count)
            except Exception as exc:
                log.error("EPSS failed: %s", exc)
                await _log(db, "epss", "error", 0, str(exc))

            # 5. Recalculate metrics
            await recalculate_metrics(db)

    log.info("Full ingest complete.")


async def _log(db, source, status, count, msg=None):
    from models import IngestLog
    db.add(IngestLog(source=source, status=status, records_processed=count, message=msg))
    await db.commit()
