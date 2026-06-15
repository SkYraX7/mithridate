"""Trust gate screener — orchestrates normalize → detect → verdict.

This is the deterministic trust boundary: every document must pass through
before any LLM sees it. Quarantined docs are stored and flagged, never
silently dropped and never passed to the extractor automatically.
"""

from __future__ import annotations

from mithridate.gate.detector import detect
from mithridate.gate.normalizer import normalize
from mithridate.models import RawDocument, ScreeningResult

# Score thresholds for verdict classification
_THRESHOLD_QUARANTINE = 0.40
_THRESHOLD_SUSPECT = 0.15


def screen(doc: RawDocument) -> tuple[RawDocument, ScreeningResult]:
    """Screen a raw document through the trust gate.

    The document's text is normalized in-place (decoded_segments populated).
    Returns the normalized document and its ScreeningResult.

    Security invariant: callers MUST NOT pass quarantined documents to the
    extractor without explicit operator approval.
    """
    all_signals: list[str] = []

    # Step 1: Normalize main text
    normalized_text, decoded_segments, norm_signals = normalize(doc.text)
    all_signals.extend(norm_signals)

    # Step 2: Run injection detection on normalized main text
    text_signals, text_score = detect(normalized_text)
    all_signals.extend(text_signals)

    # Step 3: Re-screen every decoded segment (A4 defense)
    segment_scores: list[float] = []
    for segment in decoded_segments:
        seg_norm, _, seg_norm_signals = normalize(segment)
        seg_signals, seg_score = detect(seg_norm)
        # Prefix segment signals so they're distinguishable in the audit log
        all_signals.extend(f"decoded_segment:{s}" for s in seg_norm_signals + seg_signals)
        segment_scores.append(seg_score)

    # Aggregate score: worst of main text and any decoded segment
    aggregate_score = max([text_score, *segment_scores]) if segment_scores else text_score

    # Step 4: Verdict
    if aggregate_score >= _THRESHOLD_QUARANTINE:
        verdict = "quarantine"
    elif aggregate_score >= _THRESHOLD_SUSPECT:
        verdict = "suspect"
    else:
        verdict = "clean"

    # Build updated document with decoded segments populated
    screened_doc = doc.model_copy(
        update={"text": normalized_text, "decoded_segments": decoded_segments}
    )

    result = ScreeningResult(
        doc_id=doc.id,
        verdict=verdict,
        signals=all_signals,
        score=aggregate_score,
    )

    return screened_doc, result
