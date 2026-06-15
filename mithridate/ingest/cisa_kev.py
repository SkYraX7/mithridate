"""CISA Known Exploited Vulnerabilities (KEV) ingestion source.

Fetches the KEV catalog JSON from CISA and converts each vulnerability entry
to a RawDocument. Trust tier is 'high' (government source, no user content).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

import httpx

from mithridate.ingest.base import Source
from mithridate.models import Provenance, RawDocument

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE_ID = "cisa_kev"


class CisaKevSource(Source):
    """CISA KEV catalog — high-trust government source."""

    source_id = SOURCE_ID
    trust_tier = "high"

    def __init__(self, url: str = CISA_KEV_URL, timeout: float = 30.0) -> None:
        self._url = url
        self._timeout = timeout

    def fetch(self) -> list[RawDocument]:
        logger.info("Fetching CISA KEV catalog from %s", self._url)
        try:
            response = httpx.get(self._url, timeout=self._timeout, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch CISA KEV: %s", exc)
            return []

        try:
            catalog = response.json()
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON from CISA KEV: %s", exc)
            return []

        vulnerabilities: list[dict[str, object]] = catalog.get("vulnerabilities", [])
        fetched_at = datetime.utcnow()
        documents: list[RawDocument] = []
        seen_ids: set[str] = set()

        for vuln in vulnerabilities:
            text = self._vuln_to_text(vuln)
            doc = RawDocument.from_text(
                text=text,
                provenance=Provenance(
                    source_id=SOURCE_ID,
                    url=self._url,
                    fetched_at=fetched_at,
                    trust_tier="high",
                ),
            )
            if doc.id in seen_ids:
                continue
            seen_ids.add(doc.id)
            documents.append(doc)

        logger.info("Fetched %d KEV entries", len(documents))
        return documents

    @staticmethod
    def _vuln_to_text(vuln: dict[str, object]) -> str:
        """Serialize a KEV vulnerability dict to a plain text representation."""
        fields = [
            f"CVE ID: {vuln.get('cveID', 'unknown')}",
            f"Vendor/Product: {vuln.get('vendorProject', '')} {vuln.get('product', '')}",
            f"Vulnerability Name: {vuln.get('vulnerabilityName', '')}",
            f"Date Added: {vuln.get('dateAdded', '')}",
            f"Short Description: {vuln.get('shortDescription', '')}",
            f"Required Action: {vuln.get('requiredAction', '')}",
            f"Due Date: {vuln.get('dueDate', '')}",
            f"Notes: {vuln.get('notes', '')}",
        ]
        return "\n".join(fields)
