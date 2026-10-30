"""Data models for repository scan outputs."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Citation(BaseModel):
    """Pinpoints an exact file location and evidence snippet."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    start_line: int
    end_line: int
    snippet: str


class DetectedLanguage(BaseModel):
    """Aggregate statistics for a detected programming language."""

    model_config = ConfigDict(extra="forbid")
    name: str
    files_count: int
    lines_count: int
    percentage: float


class DetectedItem(BaseModel):
    """Framework, package manager, or test tool detection result."""

    model_config = ConfigDict(extra="forbid")
    name: str
    category: str
    confidence: float
    evidence: list[Citation] = Field(default_factory=list)


class DetectedSymbol(BaseModel):
    """Key architectural code element (entrypoint, route, model, env var)."""

    model_config = ConfigDict(extra="forbid")
    name: str
    kind: str
    details: dict[str, Any] = Field(default_factory=dict)
    citation: Citation


class FileNode(BaseModel):
    """Hierarchical file tree element with line count and importance rating."""

    model_config = ConfigDict(extra="forbid")
    path: str
    is_dir: bool
    line_count: int
    size_bytes: int
    importance_score: float
    language: str | None
    children: list["FileNode"] = Field(default_factory=list)


class KeyDocument(BaseModel):
    """Content of documentation, CI, or containerization files."""

    model_config = ConfigDict(extra="forbid")
    path: str
    category: str
    content: str
    line_count: int


class ScanResult(BaseModel):
    """Comprehensive, JSON-serializable repository scan artifact."""

    model_config = ConfigDict(extra="forbid")
    repo_name: str
    repo_path: str
    total_files: int
    total_lines: int
    total_size_bytes: int
    languages: list[DetectedLanguage]
    frameworks: list[DetectedItem]
    package_managers: list[DetectedItem]
    test_tools: list[DetectedItem]
    entry_points: list[DetectedSymbol]
    routes: list[DetectedSymbol]
    db_models: list[DetectedSymbol]
    env_vars: list[DetectedSymbol]
    file_tree: FileNode
    documents: list[KeyDocument]
