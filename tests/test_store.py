"""Unit tests for the SQLite store."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from mithridate.models import (
    IOC,
    IntelRecord,
    Provenance,
    RawDocument,
    RunMetadata,
    ScreeningResult,
    TechniqueMapping,
)
from mithridate.store.db import Store


def _prov() -> Provenance:
    return Provenance(source_id="test", url=None, fetched_at=datetime.utcnow(), trust_tier="medium")


def _doc(text: str = "test content") -> RawDocument:
    return RawDocument.from_text(text, _prov())


def _screening(doc_id: str, verdict: str = "clean") -> ScreeningResult:
    return ScreeningResult(doc_id=doc_id, verdict=verdict, signals=[], score=0.0)  # type: ignore[arg-type]


@pytest.fixture
def store() -> Store:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    s = Store(db_path=db_path)
    yield s
    s.close()
    db_path.unlink(missing_ok=True)


class TestStore:
    def test_save_and_exists(self, store: Store) -> None:
        doc = _doc()
        assert not store.document_exists(doc.id)
        store.save_document(doc)
        assert store.document_exists(doc.id)

    def test_duplicate_doc_ignored(self, store: Store) -> None:
        doc = _doc()
        store.save_document(doc)
        store.save_document(doc)  # should not raise
        assert store.get_document_count() == 1

    def test_save_screening_result(self, store: Store) -> None:
        doc = _doc()
        store.save_document(doc)
        result = _screening(doc.id, "suspect")
        store.save_screening_result(result)  # should not raise

    def test_quarantine_document(self, store: Store) -> None:
        doc = _doc()
        store.save_document(doc)
        signals = ["injection:ignore_previous", "injection:verdict_override"]
        store.quarantine_document(doc.id, signals)
        quarantined = store.get_quarantined_docs()
        assert len(quarantined) == 1
        assert quarantined[0]["doc_id"] == doc.id

    def test_save_ioc_new(self, store: Store) -> None:
        ioc = IOC(
            type="ipv4",
            value="198.51.100.42",
            confidence=0.9,
            source_doc="doc1",
            first_seen=datetime.utcnow(),
        )
        is_new = store.save_ioc(ioc, run_id="run1")
        assert is_new is True
        assert store.get_ioc_count() == 1

    def test_save_ioc_duplicate(self, store: Store) -> None:
        ioc = IOC(
            type="ipv4",
            value="198.51.100.42",
            confidence=0.9,
            source_doc="doc1",
            first_seen=datetime.utcnow(),
        )
        store.save_ioc(ioc, "run1")
        is_new = store.save_ioc(ioc, "run2")
        assert is_new is False
        assert store.get_ioc_count() == 1

    def test_save_intel_record(self, store: Store) -> None:
        doc = _doc()
        store.save_document(doc)
        ioc = IOC(
            type="domain",
            value="evil.example.com",
            confidence=0.85,
            source_doc=doc.id,
            first_seen=datetime.utcnow(),
        )
        tech = TechniqueMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            confidence=0.8,
            rationale="PowerShell observed",
        )
        record = IntelRecord(
            doc_id=doc.id,
            run_id="run1",
            iocs=[ioc],
            techniques=[tech],
            screening=_screening(doc.id),
        )
        store.save_intel_record(record)
        assert store.get_ioc_count() == 1

    def test_stats(self, store: Store) -> None:
        doc = _doc()
        store.save_document(doc)
        stats = store.get_stats()
        assert stats["documents"] == 1
        assert stats["iocs"] == 0
        assert stats["quarantined"] == 0

    def test_get_ioc_lookup(self, store: Store) -> None:
        ioc = IOC(
            type="sha256",
            value="a" * 64,
            confidence=0.9,
            source_doc="doc1",
            first_seen=datetime.utcnow(),
        )
        store.save_ioc(ioc, "run1")
        found = store.get_ioc("sha256", "a" * 64)
        assert found is not None
        assert found["value"] == "a" * 64

    def test_save_and_retrieve_run(self, store: Store) -> None:
        run = RunMetadata(run_id="r1", started_at=datetime.utcnow())
        store.save_run(run)
        # No error means success — no get_run method yet, just verify no crash
