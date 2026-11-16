import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

import psycopg
from psycopg.rows import dict_row
from sqlalchemy import DateTime, ForeignKey, Text, create_engine, desc
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(Text, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    siem: Mapped[str | None] = mapped_column(Text)

    triage_result: Mapped["TriageResult"] = relationship(
        back_populates="alert",
        uselist=False,
    )


class TriageResult(Base):
    __tablename__ = "triage_results"

    alert_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("alerts.alert_id"),
        primary_key=True,
    )
    response: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    alert: Mapped[Alert] = relationship(back_populates="triage_result")


@dataclass
class AlertRow:
    alert_id: str
    response: str | None
    created_at: datetime | None
    timestamp: datetime | None
    siem: str | None = None


def _database_url() -> str:
    host = os.environ["POSTGRES_HOST"]
    port = int(os.environ.get("POSTGRES_PORT", "5432"))
    dbname = os.environ["POSTGRES_DB"]
    user = os.environ["POSTGRES_USER"]
    password = os.environ["POSTGRES_PASSWORD"]
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{dbname}"


engine = create_engine(_database_url(), future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class AlertRepository:
    @staticmethod
    def list_alert_rows(session: Session) -> list[AlertRow]:
        query = (
            session.query(Alert, TriageResult.response, TriageResult.created_at)
            .join(TriageResult, TriageResult.alert_id == Alert.alert_id)
            .order_by(desc(Alert.timestamp))
        )
        rows = query.all()

        return [
            AlertRow(
                alert_id=alert.alert_id,
                response=response,
                created_at=created_at,
                timestamp=alert.timestamp,
                siem=alert.siem,
            )
            for alert, response, created_at in rows
        ]


def get_connection():
    return psycopg.connect(
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        row_factory=dict_row,
    )


# --------------------------------------------------------------------------- SIEMs
# Same statements as the fetcher's and worker's: whichever service starts first adds them.
MULTI_SIEM_SCHEMA = """
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS siem TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS elastic_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_name TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_executable TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parent_executable TEXT;
CREATE INDEX IF NOT EXISTS alerts_siem_idx ON alerts (siem, elastic_id);
CREATE TABLE IF NOT EXISTS siems (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kibana_url TEXT, position INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
"""


def ensure_schema():
    with get_connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(7270020)")
        for statement in filter(str.strip, MULTI_SIEM_SCHEMA.split(";")):
            conn.execute(statement)


def list_siems() -> list[dict]:
    """SIEMs as the fetcher last saw siems.json, in file order (no secrets are stored here)."""
    with get_connection() as conn:
        return conn.execute("SELECT id, name, kibana_url, active FROM siems ORDER BY position, id").fetchall()


def alert_siem(alert_id: str) -> tuple[bool, str | None]:
    """(exists, siem id) of one alert. siem is None for alerts stored before multi-SIEM support."""
    with get_connection() as conn:
        row = conn.execute("SELECT siem FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
    return (row is not None, row["siem"] if row else None)


# --------------------------------------------------------------------------- trail + feedback
def get_trail(alert_id: str) -> list[dict]:
    """Steps of the most recent investigation run for this alert, in order."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT step, kind, tool_name, arguments, status, evidence_id, result, llm_content,
                      error, duration_ms, created_at
               FROM investigation_steps
               WHERE alert_id = %s AND run_id = (
                   SELECT run_id FROM investigation_steps WHERE alert_id = %s
                   ORDER BY created_at DESC LIMIT 1)
               ORDER BY step""", (alert_id, alert_id)).fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat()
    return rows


def add_feedback(alert_id, analyst, agrees, correct_verdict, comment):
    with get_connection() as conn:
        conn.execute("""INSERT INTO feedback (alert_id, analyst, agrees, correct_verdict, comment)
                        VALUES (%s, %s, %s, %s, %s)""", (alert_id, analyst, agrees, correct_verdict, comment))


def get_feedback(alert_id):
    with get_connection() as conn:
        rows = conn.execute("""SELECT analyst, agrees, correct_verdict, comment, created_at FROM feedback
                               WHERE alert_id = %s ORDER BY created_at""", (alert_id,)).fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat()
    return rows
