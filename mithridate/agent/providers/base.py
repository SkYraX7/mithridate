"""Abstract LLM provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseProvider(ABC):
    """Minimal interface for calling an LLM backend.

    The extractor uses this to make exactly one call per document.
    The provider shim is what gets swapped when changing models.
    """

    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """Send a single-turn completion request and return the response text."""
        ...
