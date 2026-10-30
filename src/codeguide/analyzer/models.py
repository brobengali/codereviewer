"""Data models for code analysis results."""

from pydantic import BaseModel, ConfigDict

from codeguide.scanner.models import Citation


class SymbolDefinition(BaseModel):
    """Extracted function, class, or method declaration with citation."""

    model_config = ConfigDict(extra="forbid")
    name: str
    kind: str
    citation: Citation
    parent: str | None = None


class ImportStatement(BaseModel):
    """Extracted import reference with citation."""

    model_config = ConfigDict(extra="forbid")
    source: str
    imported_symbols: list[str]
    is_relative: bool
    citation: Citation


class ParsedFile(BaseModel):
    """File structural breakdown parsed by tree-sitter or regex."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    language: str
    parser_used: str
    has_errors: bool
    error_line: int | None = None
    symbols: list[SymbolDefinition]
    imports: list[ImportStatement]
    lines_count: int


class DependencyNode(BaseModel):
    """Repository file node in the internal dependency graph."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    in_degree: int
    out_degree: int
    is_core: bool
    is_leaf: bool
    leaf_type: str | None = None


class DependencyEdge(BaseModel):
    """Directed dependency link between two repository files."""

    model_config = ConfigDict(extra="forbid")
    source: str
    target: str
    citation: Citation


class CircularDependency(BaseModel):
    """Detected cyclic dependency loop with file references."""

    model_config = ConfigDict(extra="forbid")
    cycle: list[str]
    citations: list[Citation]


class DependencyGraph(BaseModel):
    """Internal module dependency structure and cycle analysis."""

    model_config = ConfigDict(extra="forbid")
    nodes: list[DependencyNode]
    edges: list[DependencyEdge]
    core_modules: list[str]
    leaf_modules: list[str]
    circular_dependencies: list[CircularDependency]


class ArchitectureFinding(BaseModel):
    """Detected architectural pattern backed by repo structural evidence."""

    model_config = ConfigDict(extra="forbid")
    pattern_id: str
    name: str
    confidence: float
    description: str
    evidence_paths: list[str]
    citations: list[Citation]


class RiskSignal(BaseModel):
    """Codebase health risk indicator with exact file and line citation."""

    model_config = ConfigDict(extra="forbid")
    signal_type: str
    severity: str
    description: str
    citation: Citation


class CodeChunk(BaseModel):
    """Line-bounded code segment for chunked representation."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    chunk_index: int
    total_chunks: int
    start_line: int
    end_line: int
    content: str
    parent_symbol: str | None = None


class ParseStatus(BaseModel):
    """Statistical summary of parsing strategies and syntax issues."""

    model_config = ConfigDict(extra="forbid")
    tree_sitter_files: int
    regex_fallback_files: int
    parse_errors_count: int


class AnalysisResult(BaseModel):
    """Comprehensive typed result of repository code analysis."""

    model_config = ConfigDict(extra="forbid")
    repo_name: str
    architecture: list[ArchitectureFinding]
    dependency_graph: DependencyGraph
    symbols: list[SymbolDefinition]
    risk_signals: list[RiskSignal]
    chunks: list[CodeChunk]
    parse_status: ParseStatus
