"""Pydantic data schemas for LLM structured output, requests, and responses."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ClaimCitation(BaseModel):
    """File and line number reference backing an architectural claim."""

    path: str
    start_line: int
    end_line: int


class CodeExplanationClaim(BaseModel):
    """Individual falsifiable claim supported by citations."""

    statement: str
    citations: list[ClaimCitation] = Field(min_length=1)


class ExplanationResponse(BaseModel):
    """Structured response schema enforced across LLM generations."""

    summary: str
    architecture_overview: str
    claims: list[CodeExplanationClaim] = Field(default_factory=list)


class AnswerCitation(BaseModel):
    """Exact file and line boundary reference supporting an answer or explanation."""

    path: str
    start_line: int
    end_line: int


class AskResponse(BaseModel):
    """Structured response schema for repository question answering."""

    answer: str
    evidence_found: bool
    citations: list[AnswerCitation] = Field(default_factory=list)
    follow_up_questions: list[str] = Field(default_factory=list)


class ExplainResponse(BaseModel):
    """Structured response schema for code and symbol explanations adapted to audience."""

    target: str
    audience_level: str
    summary: str
    explanation: str
    evidence_found: bool
    citations: list[AnswerCitation] = Field(default_factory=list)
    follow_up_questions: list[str] = Field(default_factory=list)


class LLMResponse(BaseModel):
    """Execution status and structured payload from provider generation."""

    model_config = ConfigDict(extra="forbid")
    success: bool
    data: dict[str, Any] | None = None
    raw_text: str | None = None
    error: str | None = None
    cached: bool = False
    finish_reason: str | None = None


class LLMRequestPayload(BaseModel):
    """Prepared generation request payload for dry-run inspection."""

    model_config = ConfigDict(extra="forbid")
    system_prompt: str
    user_prompt: str
    model: str
    temperature: float
    max_tokens: int
    schema_definition: dict[str, Any]
    boundary_token: str
