"""FastAPI service — read-only query endpoints for the intel store.

All query inputs are treated as untrusted (MCP/API surface = trust boundary).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from mithridate.store.db import Store

app = FastAPI(
    title="Mithridate Intel API",
    description="Read-only query API for the Mithridate threat intel store.",
    version="0.1.0",
)

_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store(db_path=Path("mithridate.db"))
    return _store


class StatsResponse(BaseModel):
    documents: int
    iocs: int
    techniques: int
    quarantined: int


class IOCResponse(BaseModel):
    id: str
    type: str
    value: str
    confidence: float
    source_doc: str
    first_seen: str
    run_id: str


class TechniqueResponse(BaseModel):
    id: str
    technique_id: str
    technique_name: str
    confidence: float
    rationale: str
    source_doc: str
    run_id: str


class QuarantineResponse(BaseModel):
    doc_id: str
    reason: str
    signals: list[str]
    quarantined_at: str


@app.get("/stats", response_model=StatsResponse)
def stats() -> StatsResponse:
    return StatsResponse(**get_store().get_stats())


@app.get("/iocs", response_model=list[IOCResponse])
def list_iocs(
    limit: int = Query(50, ge=1, le=1000),
    ioc_type: str | None = Query(None),
) -> list[IOCResponse]:
    rows = get_store().get_recent_iocs(limit=limit)
    if ioc_type:
        rows = [r for r in rows if r["type"] == ioc_type]
    return [IOCResponse(**r) for r in rows]  # type: ignore[arg-type]


@app.get("/iocs/lookup")
def lookup_ioc(type: str = Query(...), value: str = Query(...)) -> dict[str, object]:
    row = get_store().get_ioc(type, value)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")
    return row  # type: ignore[return-value]


@app.get("/techniques", response_model=list[TechniqueResponse])
def list_techniques(limit: int = Query(50, ge=1, le=1000)) -> list[TechniqueResponse]:
    rows = get_store().get_recent_techniques(limit=limit)
    return [TechniqueResponse(**r) for r in rows]  # type: ignore[arg-type]


@app.get("/quarantine", response_model=list[QuarantineResponse])
def list_quarantined() -> list[QuarantineResponse]:
    rows = get_store().get_quarantined_docs()
    return [QuarantineResponse(**r) for r in rows]  # type: ignore[arg-type]


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}
