"""IOC extraction tool — validates and normalizes raw candidate indicators.

This tool accepts raw candidate IOCs from the extractor's output and runs
them through strict per-type validation. Invalid forms are rejected and
logged; overflow is flagged per §7.4 (anti-flooding, A3 defense).
"""

from __future__ import annotations

import logging

from mithridate.models import (
    IOC,
    IOC_PATTERNS,
    ExtractIOCsInput,
    ExtractIOCsOutput,
    _refang,
)

logger = logging.getLogger(__name__)

PER_DOCUMENT_IOC_CAP = 200
"""Maximum IOCs persisted from a single document (A3: anti-flooding)."""


def extract_iocs(input_data: ExtractIOCsInput) -> ExtractIOCsOutput:
    """Validate candidate IOCs and return those that pass strict format checks.

    Security: this is the output-validation gate for IOCs (§7.4).
    Any IOC that fails format validation is rejected and logged.
    Overflow beyond PER_DOCUMENT_IOC_CAP is flagged for review.
    """
    valid: list[IOC] = []
    rejected: list[dict[str, str]] = []

    for candidate in input_data.raw_candidates:
        ioc_type = candidate.get("type", "").lower()
        raw_value = candidate.get("value", "").strip()

        if ioc_type not in IOC_PATTERNS:
            rejected.append({"type": ioc_type, "value": raw_value, "reason": "unknown_type"})
            continue

        canonical = _refang(raw_value)
        pattern = IOC_PATTERNS[ioc_type]  # type: ignore[literal-required]
        if not pattern.match(canonical):
            rejected.append({"type": ioc_type, "value": raw_value, "reason": "format_mismatch"})
            logger.debug("Rejected IOC: type=%s value=%r (format mismatch)", ioc_type, raw_value)
            continue

        try:
            confidence_raw = float(candidate.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence_raw))
        except (ValueError, TypeError):
            confidence = 0.5

        try:
            ioc = IOC(
                type=ioc_type,  # type: ignore[arg-type]
                value=canonical,
                confidence=confidence,
                source_doc=input_data.source_doc_id,
                first_seen=input_data.timestamp,
            )
            valid.append(ioc)
        except Exception as exc:
            rejected.append({"type": ioc_type, "value": raw_value, "reason": str(exc)})

    overflow_flagged = False
    if len(valid) > PER_DOCUMENT_IOC_CAP:
        logger.warning(
            "Document %s produced %d IOCs (cap=%d) — overflow flagged for review",
            input_data.source_doc_id,
            len(valid),
            PER_DOCUMENT_IOC_CAP,
        )
        valid = valid[:PER_DOCUMENT_IOC_CAP]
        overflow_flagged = True

    if rejected:
        logger.info(
            "Rejected %d invalid IOC candidates from doc %s",
            len(rejected),
            input_data.source_doc_id,
        )

    return ExtractIOCsOutput(
        iocs=valid,
        rejected=rejected,
        overflow_flagged=overflow_flagged,
    )
