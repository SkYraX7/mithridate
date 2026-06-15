"""Base class for ingestion source plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mithridate.models import RawDocument


class Source(ABC):
    """Abstract base for an OSINT source plugin.

    Each implementation fetches raw documents from one source and normalizes
    them to RawDocument. No content interpretation happens here.
    """

    source_id: str
    trust_tier: str

    @abstractmethod
    def fetch(self) -> list[RawDocument]:
        """Fetch and return raw documents from this source.

        Implementations MUST NOT attempt to parse indicators from the content —
        that is the agent's job under quarantine.
        """
        ...
