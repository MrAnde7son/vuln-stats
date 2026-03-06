# VulnStats – Live Vulnerability Intelligence Dashboard

A real-time web application that tracks **MTTR** (Mean Time to Remediate),
**MTTE** (Mean Time to Exploit), and **Exposure Window** across CVEs — broken
down by domain (OS, Cloud, SaaS, Web Apps) and visualised with rolling-average
trend charts.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Browser                          │
│   Chart.js dashboard  ←─ REST JSON ─→  FastAPI backend  │
└──────────────────────────────────┬──────────────────────┘
                                   │
              ┌────────────────────▼──────────────────────┐
              │          Ingestion Engine (daily)          │
              │  CISA KEV → exploit dates                  │
              │  NVD 2.0  → disclosure, CVSS, CPE, CWE    │
              │  OSV.dev  → fix/patch dates                │
              │  EPSS API → exploit probability scores     │
              └────────────────────┬──────────────────────┘
                                   │
              ┌────────────────────▼──────────────────────┐
              │          SQLite  (vuln_stats.db)           │
              │  MTTR = fixed_date  − published_date       │
              │  MTTE = exploited_date − published_date    │
              │  Exposure = MTTR − MTTE                    │
              └───────────────────────────────────────────┘
```

## Quick Start

### With Docker (recommended)

```bash
docker compose up --build
```

Open <http://localhost:8000>.

### Local dev

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open <http://localhost:8000>.

On first boot the app will automatically ingest data from all four live APIs.
A daily cron job at 03:00 UTC re-runs the ingest. You can also trigger a
manual ingest from the dashboard (⬇ Re-Ingest button) or via:

```bash
curl -X POST http://localhost:8000/api/ingest/trigger
```

---

## Data Sources

| Source | What it provides | Endpoint |
|--------|-----------------|----------|
| **CISA KEV** | "Exploited in the wild" dates | `cisa.gov/…/known_exploited_vulnerabilities.json` |
| **NVD API 2.0** | Disclosure dates, CVSS scores, CPE/CWE | `services.nvd.nist.gov/rest/json/cves/2.0` |
| **OSV.dev** | Fix/patch dates for open-source packages | `api.osv.dev/v1/query` |
| **EPSS (FIRST)** | Daily exploit-probability scores | `api.first.org/data/v1/epss` |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | Aggregate KPIs (optional `?domain=`) |
| GET | `/api/trends` | Monthly MTTR/MTTE trend (`?months=24&domain=`) |
| GET | `/api/domains` | Per-domain breakdown |
| GET | `/api/cves` | Paginated CVE list (filters: `domain`, `kev_only`, `min_cvss`) |
| GET | `/api/cves/{id}` | Single CVE detail |
| GET | `/api/epss/distribution` | EPSS score histogram |
| GET | `/api/ingest/status` | Last 20 ingest run logs |
| POST | `/api/ingest/trigger` | Manually start an ingest |

---

## Metrics Explained

| Metric | Formula | Why it matters |
|--------|---------|----------------|
| **MTTR** | `Date Fixed − Date Published` | How long orgs are exposed before a patch exists |
| **MTTE** | `Date Exploited − Date Published` | How quickly attackers weaponize a CVE |
| **Exposure Window** | `MTTR − MTTE` | Positive = patch came after exploit; negative = patch beat attackers |

---

## Domain Classification

CPE strings from NVD are matched against keyword prefixes:

| Domain | Detection logic |
|--------|----------------|
| `os` | CPE `o:microsoft:windows`, `o:linux:linux_kernel`, `o:apple:macos`, … |
| `cloud` | CPE `a:amazon:aws`, `a:google:cloud`, `a:microsoft:azure`, `a:kubernetes`, … |
| `saas` | CPE `a:salesforce`, `a:atlassian:jira`, `a:zoom`, `a:slack`, … |
| `webapp` | CPE `a:apache:http_server`, `a:wordpress`, … or CWE-79/89/352 |
| `other` | Everything else |
