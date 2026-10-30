"""Data models for redaction operations."""

from pydantic import BaseModel, ConfigDict, Field


class RedactedFinding(BaseModel):
    """Metadata regarding a detected and sanitized secret."""

    model_config = ConfigDict(extra="forbid")
    rule_id: str
    placeholder: str
    line_number: int
    masked_preview: str


class RedactionResult(BaseModel):
    """Result of text sanitization including clean text and audit records."""

    model_config = ConfigDict(extra="forbid")
    clean_text: str
    findings: list[RedactedFinding] = Field(default_factory=list)
