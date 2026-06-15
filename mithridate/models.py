"""Canonical Pydantic v2 schemas. Every field crossing a trust boundary is validated here.

Schemas are a security control: strict types and validators prevent malformed or
adversarially-crafted values from entering the store.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# IOC format validators — strict per-type regex patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6 = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    r"|^(?:[0-9a-fA-F]{1,4}:)*:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"
    r"|^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"
    r"|^::$"
)
_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]*$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": _IPV4,
    "ipv6": _IPV6,
    "domain": _DOMAIN,
    "url": _URL,
    "md5": _MD5,
    "sha1": _SHA1,
    "sha256": _SHA256,
    "email": _EMAIL,
    "cve": _CVE,
}

IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve"]
TrustTier = Literal["high", "medium", "low"]
Verdict = Literal["clean", "suspect", "quarantine"]


def _refang(value: str) -> str:
    """Convert defanged indicators back to canonical form before validation."""
    return (
        value.replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
        .replace("[.]", ".")
        .replace("(dot)", ".")
        .replace("[at]", "@")
        .replace("(@)", "@")
    )


# ---------------------------------------------------------------------------
# Core schemas (§6 of DESIGN.md)
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    source_id: str
    url: str | None = None
    fetched_at: datetime
    trust_tier: TrustTier


class RawDocument(BaseModel):
    """A single document ingested from an external source. TAINTED — never trusted."""

    id: str
    text: str
    decoded_segments: list[str] = Field(default_factory=list)
    provenance: Provenance

    @classmethod
    def from_text(cls, text: str, provenance: Provenance) -> RawDocument:
        doc_id = hashlib.sha256(text.encode()).hexdigest()
        return cls(id=doc_id, text=text, provenance=provenance)


class ScreeningResult(BaseModel):
    doc_id: str
    verdict: Verdict
    signals: list[str]
    score: float = Field(ge=0.0, le=1.0)

    @field_validator("score")
    @classmethod
    def clamp_score(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class IOC(BaseModel):
    """A validated indicator of compromise. Format must pass strict regex before construction."""

    type: IOCType
    value: str
    confidence: float = Field(default=0.5)
    source_doc: str
    first_seen: datetime

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: object) -> float:
        return max(0.0, min(1.0, float(v)))  # type: ignore[arg-type]

    @model_validator(mode="after")
    def check_ioc_format(self) -> "IOC":
        canonical = _refang(self.value)
        pattern = IOC_PATTERNS[self.type]
        if not pattern.match(canonical):
            raise ValueError(
                f"IOC value {self.value!r} does not match pattern for type {self.type!r}"
            )
        self.value = canonical
        return self


class TechniqueMapping(BaseModel):
    technique_id: str
    technique_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str

    @field_validator("technique_id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        normalized = v.upper().strip()
        if not _ATTACK_ID.match(normalized):
            raise ValueError(
                f"ATT&CK technique ID {v!r} does not match expected format TXXXX[.XXX]"
            )
        return normalized


class IntelRecord(BaseModel):
    doc_id: str
    run_id: str
    iocs: list[IOC]
    techniques: list[TechniqueMapping]
    screening: ScreeningResult
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Eval corpus schema
# ---------------------------------------------------------------------------


class GroundTruthIOC(BaseModel):
    type: IOCType
    value: str


class GroundTruth(BaseModel):
    iocs: list[GroundTruthIOC] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)


class CorpusDocument(BaseModel):
    """A document in the eval corpus with ground-truth labels."""

    id: str
    text: str
    is_poisoned: bool
    attack_scenario: str | None = None
    expected_verdict: Verdict | None = None
    ground_truth: GroundTruth | None = None


# ---------------------------------------------------------------------------
# Run metadata
# ---------------------------------------------------------------------------


class RunMetadata(BaseModel):
    run_id: str
    started_at: datetime
    completed_at: datetime | None = None
    docs_processed: int = 0
    docs_quarantined: int = 0
    iocs_extracted: int = 0
    techniques_mapped: int = 0


# ---------------------------------------------------------------------------
# Tool I/O schemas — each tool call has a validated input and output
# ---------------------------------------------------------------------------


class ExtractIOCsInput(BaseModel):
    raw_candidates: list[dict[str, Any]]
    source_doc_id: str
    timestamp: datetime


class ExtractIOCsOutput(BaseModel):
    iocs: list[IOC]
    rejected: list[dict[str, str]]
    overflow_flagged: bool = False


class MapAttackInput(BaseModel):
    candidate_ids: list[str]
    rationales: dict[str, str]
    source_doc_id: str


class MapAttackOutput(BaseModel):
    mappings: list[TechniqueMapping]
    hallucinated: list[str]


class ScoreConfidenceInput(BaseModel):
    iocs: list[IOC]
    techniques: list[TechniqueMapping]
    screening_score: float
    trust_tier: TrustTier


class ScoreConfidenceOutput(BaseModel):
    iocs: list[IOC]
    techniques: list[TechniqueMapping]


class DedupeCheckInput(BaseModel):
    iocs: list[IOC]
    techniques: list[TechniqueMapping]


class DedupeCheckOutput(BaseModel):
    new_iocs: list[IOC]
    duplicate_ioc_count: int
    new_techniques: list[TechniqueMapping]
    duplicate_technique_count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_text(text: str) -> str:
    """NFKC Unicode normalization — applied before gate screening."""
    return unicodedata.normalize("NFKC", text)
