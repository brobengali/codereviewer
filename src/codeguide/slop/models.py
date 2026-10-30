"""Data models representing slop violations, documentation lint results, and code lint results."""

from pydantic import BaseModel, ConfigDict, Field


class SlopViolation(BaseModel):
    """Specific detected slop violation within documentation or source code."""

    model_config = ConfigDict(extra="forbid")
    category: str
    file_path: str
    line_number: int
    message: str
    snippet: str
    severity: float


class DocLintResult(BaseModel):
    """Comprehensive result of auditing a documentation artifact for slop."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    violations: list[SlopViolation] = Field(default_factory=list)
    total_sentences: int
    slop_score: float
    passed: bool


class CodeLintResult(BaseModel):
    """Comprehensive result of auditing codebase source files for code slop."""

    model_config = ConfigDict(extra="forbid")
    repo_path: str
    violations: list[SlopViolation] = Field(default_factory=list)
    files_scanned: int
    slop_score: float
    passed: bool
