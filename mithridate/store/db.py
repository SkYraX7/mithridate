"""SQLite persistence layer.

Tables:
  raw_documents      — every ingested document (tainted)
  screening_results  — gate verdict + signals per document
  quarantined_docs   — documents that failed screening (stored, never silently dropped)
  iocs               — validated indicators of compromise
  technique_mappings — ATT&CK technique associations
  intel_records      — links iocs + techniques to a run
  run_metadata       — pipeline run summaries

Full lineage is maintained: every IOC and technique carries run_id,
source provenance, and the screening verdict from its document.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from mithridate.models import (
    IOC,
    IntelRecord,
    RawDocument,
    RunMetadata,
    ScreeningResult,
    TechniqueMapping,
)

DEFAULT_DB_PATH = Path("mithridate.db")


class Store:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._tx() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS raw_documents (
                    id          TEXT PRIMARY KEY,
                    text        TEXT NOT NULL,
                    source_id   TEXT NOT NULL,
                    url         TEXT,
                    fetched_at  TEXT NOT NULL,
                    trust_tier  TEXT NOT NULL,
                    ingested_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS screening_results (
                    doc_id   TEXT PRIMARY KEY REFERENCES raw_documents(id),
                    verdict  TEXT NOT NULL,
                    signals  TEXT NOT NULL,  -- JSON array
                    score    REAL NOT NULL,
                    screened_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS quarantined_docs (
                    doc_id     TEXT PRIMARY KEY REFERENCES raw_documents(id),
                    reason     TEXT NOT NULL,
                    signals    TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id          TEXT PRIMARY KEY,  -- type:value hash
                    type        TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    confidence  REAL NOT NULL,
                    source_doc  TEXT NOT NULL,
                    first_seen  TEXT NOT NULL,
                    run_id      TEXT NOT NULL,
                    UNIQUE(type, value)
                );

                CREATE TABLE IF NOT EXISTS technique_mappings (
                    id              TEXT PRIMARY KEY,
                    technique_id    TEXT NOT NULL,
                    technique_name  TEXT NOT NULL,
                    confidence      REAL NOT NULL,
                    rationale       TEXT NOT NULL,
                    source_doc      TEXT NOT NULL,
                    run_id          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS intel_records (
                    doc_id      TEXT PRIMARY KEY,
                    run_id      TEXT NOT NULL,
                    verdict     TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS run_metadata (
                    run_id          TEXT PRIMARY KEY,
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT,
                    docs_processed  INTEGER DEFAULT 0,
                    docs_quarantined INTEGER DEFAULT 0,
                    iocs_extracted  INTEGER DEFAULT 0,
                    techniques_mapped INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_techniques_id ON technique_mappings(technique_id);
            """)

    # ------------------------------------------------------------------
    # Raw documents
    # ------------------------------------------------------------------

    def save_document(self, doc: RawDocument) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO raw_documents
                    (id, text, source_id, url, fetched_at, trust_tier, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc.id,
                    doc.text,
                    doc.provenance.source_id,
                    doc.provenance.url,
                    doc.provenance.fetched_at.isoformat(),
                    doc.provenance.trust_tier,
                    datetime.utcnow().isoformat(),
                ),
            )

    def document_exists(self, doc_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM raw_documents WHERE id = ?", (doc_id,)
        ).fetchone()
        return row is not None

    def get_document_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM raw_documents").fetchone()
        return int(row[0])

    # ------------------------------------------------------------------
    # Screening results
    # ------------------------------------------------------------------

    def save_screening_result(self, result: ScreeningResult) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO screening_results
                    (doc_id, verdict, signals, score, screened_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.doc_id,
                    result.verdict,
                    json.dumps(result.signals),
                    result.score,
                    datetime.utcnow().isoformat(),
                ),
            )

    def quarantine_document(self, doc_id: str, signals: list[str]) -> None:
        reason = "; ".join(signals[:5]) if signals else "score_threshold"
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO quarantined_docs
                    (doc_id, reason, signals, quarantined_at)
                VALUES (?, ?, ?, ?)
                """,
                (doc_id, reason, json.dumps(signals), datetime.utcnow().isoformat()),
            )

    def get_quarantined_docs(self) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT doc_id, reason, signals, quarantined_at FROM quarantined_docs ORDER BY quarantined_at DESC"
        ).fetchall()
        return [
            {
                "doc_id": r["doc_id"],
                "reason": r["reason"],
                "signals": json.loads(r["signals"]),
                "quarantined_at": r["quarantined_at"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def save_ioc(self, ioc: IOC, run_id: str) -> bool:
        """Save an IOC. Returns True if new, False if duplicate."""
        ioc_id = f"{ioc.type}:{ioc.value}"
        with self._tx() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO iocs
                        (id, type, value, confidence, source_doc, first_seen, run_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ioc_id,
                        ioc.type,
                        ioc.value,
                        ioc.confidence,
                        ioc.source_doc,
                        ioc.first_seen.isoformat(),
                        run_id,
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_ioc(self, ioc_type: str, value: str) -> dict[str, object] | None:
        row = self._conn.execute(
            "SELECT * FROM iocs WHERE type = ? AND value = ?", (ioc_type, value)
        ).fetchone()
        return dict(row) if row else None

    def get_ioc_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
        return int(row[0])

    # ------------------------------------------------------------------
    # Technique mappings
    # ------------------------------------------------------------------

    def save_technique(self, mapping: TechniqueMapping, source_doc: str, run_id: str) -> None:
        import hashlib

        mapping_id = hashlib.sha256(
            f"{mapping.technique_id}:{source_doc}:{run_id}".encode()
        ).hexdigest()[:16]
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO technique_mappings
                    (id, technique_id, technique_name, confidence, rationale, source_doc, run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping_id,
                    mapping.technique_id,
                    mapping.technique_name,
                    mapping.confidence,
                    mapping.rationale,
                    source_doc,
                    run_id,
                ),
            )

    # ------------------------------------------------------------------
    # Intel records
    # ------------------------------------------------------------------

    def save_intel_record(self, record: IntelRecord) -> None:
        now = datetime.utcnow().isoformat()
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO intel_records (doc_id, run_id, verdict, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (record.doc_id, record.run_id, record.screening.verdict, now),
            )
        for ioc in record.iocs:
            self.save_ioc(ioc, record.run_id)
        for tech in record.techniques:
            self.save_technique(tech, record.doc_id, record.run_id)

    # ------------------------------------------------------------------
    # Run metadata
    # ------------------------------------------------------------------

    def save_run(self, run: RunMetadata) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO run_metadata
                    (run_id, started_at, completed_at, docs_processed,
                     docs_quarantined, iocs_extracted, techniques_mapped)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.started_at.isoformat(),
                    run.completed_at.isoformat() if run.completed_at else None,
                    run.docs_processed,
                    run.docs_quarantined,
                    run.iocs_extracted,
                    run.techniques_mapped,
                ),
            )

    def get_stats(self) -> dict[str, int]:
        return {
            "documents": self.get_document_count(),
            "iocs": self.get_ioc_count(),
            "techniques": int(
                self._conn.execute("SELECT COUNT(*) FROM technique_mappings").fetchone()[0]
            ),
            "quarantined": int(
                self._conn.execute("SELECT COUNT(*) FROM quarantined_docs").fetchone()[0]
            ),
        }

    def get_recent_iocs(self, limit: int = 50) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM iocs ORDER BY first_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_techniques(self, limit: int = 50) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM technique_mappings ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
