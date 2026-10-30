"""Abstract LLM provider interface definition."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class LLMProvider(ABC):
    """Abstract interface defining required generation capabilities for providers."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        schema: type[BaseModel],
        system_instruction: str | None = None,
    ) -> dict[str, Any]:
        """Executes completion request and returns a validated dictionary matching the schema."""
        pass
