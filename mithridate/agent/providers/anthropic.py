"""Anthropic Claude provider shim."""

from __future__ import annotations

import logging
import os

from mithridate.agent.providers.base import BaseProvider

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(BaseProvider):
    """Calls Anthropic's Claude API.

    Requires ANTHROPIC_API_KEY in the environment.
    Uses temperature=0 by default for deterministic extraction.
    """

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self._api_key:
            logger.warning(
                "ANTHROPIC_API_KEY not set — LLM calls will fail. "
                "Set the env var or pass api_key= to AnthropicProvider."
            )

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                "anthropic package not installed — run: pip install anthropic"
            ) from exc

        client = anthropic.Anthropic(api_key=self._api_key)
        message = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return str(message.content[0].text)  # type: ignore[union-attr]
