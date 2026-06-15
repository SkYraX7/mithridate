"""Content-blind planner / orchestrator.

The planner decides what to do based on document METADATA only — never raw text.
It sequences the tool calls explicitly in Python; document content has no path to
select, add, reorder, or parameterize these calls.

Pipeline per document:
  1. Gate screens the document (normalizer → detector → verdict)
  2. If quarantine: store, flag, return early (no LLM call)
  3. If clean|suspect: call extractor (quarantined LLM, sees content as data)
  4. Validate extracted IOCs (extract_iocs tool)
  5. Validate ATT&CK mappings (map_attack tool)
  6. Adjust confidence scores (score_confidence tool)
  7. Deduplicate (dedupe_check tool)
  8. Persist IntelRecord
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from mithridate.agent.extractor import BATCH_SIZE, extract_raw_batch
from mithridate.agent.providers.base import BaseProvider
from mithridate.agent.tools.dedupe_check import dedupe_check
from mithridate.agent.tools.extract_iocs import extract_iocs
from mithridate.agent.tools.map_attack import map_attack
from mithridate.agent.tools.score_confidence import score_confidence
from mithridate.gate.screener import screen
from mithridate.models import (
    DedupeCheckInput,
    ExtractIOCsInput,
    IntelRecord,
    MapAttackInput,
    RawDocument,
    RunMetadata,
    ScoreConfidenceInput,
    ScreeningResult,
)
from mithridate.store.db import Store

logger = logging.getLogger(__name__)


class PipelineResult:
    """Result of running the pipeline on one document."""

    def __init__(
        self,
        doc_id: str,
        screening: ScreeningResult,
        record: IntelRecord | None,
        hallucinated_techniques: list[str],
        overflow_flagged: bool,
        rejected_iocs: list[dict[str, str]],
    ) -> None:
        self.doc_id = doc_id
        self.screening = screening
        self.record = record
        self.hallucinated_techniques = hallucinated_techniques
        self.overflow_flagged = overflow_flagged
        self.rejected_iocs = rejected_iocs

    @property
    def was_quarantined(self) -> bool:
        return self.screening.verdict == "quarantine"

    @property
    def ioc_count(self) -> int:
        return len(self.record.iocs) if self.record else 0

    @property
    def technique_count(self) -> int:
        return len(self.record.techniques) if self.record else 0


class Planner:
    """Orchestrates the full pipeline. Never sees raw document text."""

    def __init__(self, provider: BaseProvider, store: Store) -> None:
        self._provider = provider
        self._store = store

    def _process_screened(
        self,
        screened_doc: RawDocument,
        screening_result: ScreeningResult,
        raw_candidates: dict[str, Any],
        run_id: str,
    ) -> PipelineResult:
        """Run steps 4-8 on a document that has already passed the gate and been extracted."""
        extraction_ts = datetime.utcnow()

        # --- Step 4: Validate IOCs ---
        ioc_output = extract_iocs(
            ExtractIOCsInput(
                raw_candidates=raw_candidates.get("iocs", []),
                source_doc_id=screened_doc.id,
                timestamp=extraction_ts,
            )
        )

        # --- Step 5: Validate ATT&CK mappings ---
        raw_techniques = raw_candidates.get("techniques", [])
        candidate_ids = [t.get("technique_id", "") for t in raw_techniques]
        rationales = {t.get("technique_id", ""): t.get("rationale", "") for t in raw_techniques}

        attack_output = map_attack(
            MapAttackInput(
                candidate_ids=candidate_ids,
                rationales=rationales,
                source_doc_id=screened_doc.id,
            )
        )

        for mapping in attack_output.mappings:
            for raw_t in raw_techniques:
                if raw_t.get("technique_id", "").upper() == mapping.technique_id:
                    raw_conf = raw_t.get("confidence", 0.7)
                    try:
                        mapping = mapping.model_copy(update={"confidence": float(raw_conf)})
                    except (ValueError, TypeError):
                        pass
                    break

        # --- Step 6: Confidence scoring ---
        scored_output = score_confidence(
            ScoreConfidenceInput(
                iocs=ioc_output.iocs,
                techniques=attack_output.mappings,
                screening_score=screening_result.score,
                trust_tier=screened_doc.provenance.trust_tier,
            )
        )

        # --- Step 7: Deduplication ---
        deduped = dedupe_check(
            DedupeCheckInput(
                iocs=scored_output.iocs,
                techniques=scored_output.techniques,
            ),
            ioc_exists=lambda t, v: self._store.get_ioc(t, v) is not None,
        )

        logger.info(
            "doc=%s iocs_new=%d dups=%d techs_new=%d hallucinated=%d",
            screened_doc.id[:12],
            len(deduped.new_iocs),
            deduped.duplicate_ioc_count,
            len(deduped.new_techniques),
            len(attack_output.hallucinated),
        )

        # --- Step 8: Persist ---
        intel_record = IntelRecord(
            doc_id=screened_doc.id,
            run_id=run_id,
            iocs=deduped.new_iocs,
            techniques=deduped.new_techniques,
            screening=screening_result,
        )
        self._store.save_intel_record(intel_record)

        return PipelineResult(
            doc_id=screened_doc.id,
            screening=screening_result,
            record=intel_record,
            hallucinated_techniques=attack_output.hallucinated,
            overflow_flagged=ioc_output.overflow_flagged,
            rejected_iocs=ioc_output.rejected,
        )

    def _call_extractor(
        self,
        batch: list[tuple[RawDocument, ScreeningResult]],
    ) -> tuple[list[tuple[RawDocument, ScreeningResult]], list[dict[str, Any]]]:
        """Run extract_raw_batch for one batch. Runs in a worker thread — no DB access."""
        texts = [doc.text for doc, _ in batch]
        raw_results = extract_raw_batch(texts, self._provider)
        return batch, raw_results

    def run_batch(
        self,
        documents: list[RawDocument],
        on_gate_done: Callable[[], None] | None = None,
        on_extract_done: Callable[[int, int, int], None] | None = None,
        max_workers: int = 5,
    ) -> RunMetadata:
        """Process documents in gate-then-parallel-batch-extract pipeline.

        Phase 1 (gate): sequential, deterministic, no I/O — fast.
        Phase 2 (extract): up to max_workers concurrent API calls, each covering
          BATCH_SIZE docs. All DB writes happen on the main thread after each
          future resolves, so SQLite is never accessed concurrently.

        Callbacks (optional, for CLI progress display):
          on_gate_done()                         — called after each gate verdict
          on_extract_done(n_docs, iocs, techs)   — called after each batch is written
        """
        run_id = str(uuid.uuid4())
        started_at = datetime.utcnow()
        run = RunMetadata(run_id=run_id, started_at=started_at)

        # Phase 1: gate all documents (sequential — pure Python, no I/O)
        screened_pairs: list[tuple[RawDocument, ScreeningResult]] = []
        for doc in documents:
            screened_doc, screening_result = screen(doc)
            logger.info(
                "doc=%s verdict=%s score=%.3f",
                doc.id[:12],
                screening_result.verdict,
                screening_result.score,
            )
            self._store.save_document(screened_doc)
            self._store.save_screening_result(screening_result)

            run.docs_processed += 1
            if screening_result.verdict == "quarantine":
                self._store.quarantine_document(doc.id, screening_result.signals)
                logger.warning("Quarantined doc=%s", doc.id[:12])
                run.docs_quarantined += 1
            else:
                screened_pairs.append((screened_doc, screening_result))

            if on_gate_done:
                on_gate_done()

        # Phase 2: concurrent API calls, serial DB writes
        # Worker threads handle only the Anthropic HTTP round-trip.
        # The main thread collects results via as_completed and owns all DB writes,
        # so SQLite is never touched from more than one thread simultaneously.
        batches = [
            screened_pairs[i : i + BATCH_SIZE]
            for i in range(0, len(screened_pairs), BATCH_SIZE)
        ]
        logger.info(
            "Dispatching %d batches across %d workers (batch_size=%d)",
            len(batches),
            min(max_workers, len(batches)),
            BATCH_SIZE,
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._call_extractor, batch): batch
                for batch in batches
            }

            for future in as_completed(future_map):
                try:
                    batch, raw_results = future.result()
                except RuntimeError as exc:
                    batch = future_map[future]
                    logger.error(
                        "Extractor batch failed (%d docs): %s",
                        len(batch),
                        exc,
                    )
                    if on_extract_done:
                        on_extract_done(len(batch), 0, 0)
                    continue

                # DB writes — main thread only
                batch_iocs = batch_techs = 0
                for (screened_doc, screening_result), raw_candidates in zip(batch, raw_results):
                    result = self._process_screened(
                        screened_doc, screening_result, raw_candidates, run_id
                    )
                    run.iocs_extracted += result.ioc_count
                    run.techniques_mapped += result.technique_count
                    batch_iocs += result.ioc_count
                    batch_techs += result.technique_count

                if on_extract_done:
                    on_extract_done(len(batch), batch_iocs, batch_techs)

        run.completed_at = datetime.utcnow()
        self._store.save_run(run)
        return run
