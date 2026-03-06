from sqlalchemy import Column, String, Float, Date, DateTime, Integer, Text
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime


class Base(DeclarativeBase):
    pass


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id = Column(String, primary_key=True, index=True)
    description = Column(Text, nullable=True)
    published_date = Column(Date, nullable=True)
    fixed_date = Column(Date, nullable=True)
    exploited_date = Column(Date, nullable=True)
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    domain = Column(String, nullable=True)  # os, cloud, saas, webapp, other
    cpe_data = Column(Text, nullable=True)  # raw CPE string(s)
    cwe_ids = Column(Text, nullable=True)   # comma-separated CWE IDs
    mttr_days = Column(Float, nullable=True)
    mtte_days = Column(Float, nullable=True)
    exposure_window_days = Column(Float, nullable=True)
    in_kev = Column(Integer, default=0)     # 1 if in CISA KEV
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IngestLog(Base):
    __tablename__ = "ingest_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String)
    status = Column(String)
    records_processed = Column(Integer, default=0)
    message = Column(Text, nullable=True)
    ran_at = Column(DateTime, default=datetime.utcnow)
