"""LLM orchestration package."""

from codeguide.llm.base import LLMProvider
from codeguide.llm.cache import LLMCache
from codeguide.llm.engine import LLMEngine
from codeguide.llm.gemini import GoogleGenAIProvider
from codeguide.llm.key import KeyMaskingFilter, SecretKey, resolve_api_key
from codeguide.llm.local import LocalProvider
from codeguide.llm.models import (
    ClaimCitation,
    CodeExplanationClaim,
    ExplanationResponse,
    LLMRequestPayload,
    LLMResponse,
)

GeminiProvider = GoogleGenAIProvider

__all__ = [
    "ClaimCitation",
    "CodeExplanationClaim",
    "ExplanationResponse",
    "GoogleGenAIProvider",
    "KeyMaskingFilter",
    "LLMCache",
    "LLMEngine",
    "LLMProvider",
    "LLMRequestPayload",
    "LLMResponse",
    "LocalProvider",
    "SecretKey",
    "resolve_api_key",
]
