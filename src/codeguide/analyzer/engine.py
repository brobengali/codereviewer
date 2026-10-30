"""Repository analyzer orchestrating AST parsing, graph analysis, and pattern detection."""

import logging
from pathlib import Path

from codeguide.analyzer.architecture import ArchitectureDetector
from codeguide.analyzer.chunker import FileChunker
from codeguide.analyzer.dependency import DependencyAnalyzer
from codeguide.analyzer.grammars import GrammarRegistry
from codeguide.analyzer.models import (
    AnalysisResult,
    CodeChunk,
    ParsedFile,
    ParseStatus,
    RiskSignal,
    SymbolDefinition,
)
from codeguide.analyzer.parser import CodeParser
from codeguide.analyzer.risks import RiskAnalyzer
from codeguide.config.models import AppConfig
from codeguide.scanner.models import FileNode, ScanResult

logger = logging.getLogger("codeguide.analyzer")


class RepositoryAnalyzer:
    """Performs deep static analysis across repository files."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.registry = GrammarRegistry(config)
        self.parser = CodeParser(self.registry)
        self.arch_detector = ArchitectureDetector(config)
        self.chunker = FileChunker(config)

    def _collect_file_nodes(self, node: FileNode) -> list[FileNode]:
        nodes: list[FileNode] = []
        if not node.is_dir and node.path:
            nodes.append(node)
        for child in node.children:
            nodes.extend(self._collect_file_nodes(child))
        return nodes

    def analyze(self, repo_dir: Path, scan_result: ScanResult) -> AnalysisResult:
        file_nodes = self._collect_file_nodes(scan_result.file_tree)
        known_files = [
            f.path
            for f in file_nodes
            if Path(f.path).suffix.lower() not in self.config.analysis.binary_extensions
        ]
        dep_analyzer = DependencyAnalyzer(self.config, known_files)
        risk_analyzer = RiskAnalyzer(self.config, known_files)

        parsed_files: list[ParsedFile] = []
        all_symbols: list[SymbolDefinition] = []
        all_risks: list[RiskSignal] = []
        all_chunks: list[CodeChunk] = []

        ts_count = 0
        regex_count = 0
        error_count = 0

        for f_node in file_nodes:
            ext = Path(f_node.path).suffix.lower()
            if ext in self.config.analysis.binary_extensions:
                continue

            full_path = repo_dir / f_node.path
            if not full_path.is_file():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                logger.debug("Failed reading file %s for analysis: %s", f_node.path, exc)
                continue

            language = (
                f_node.language or self.registry.get_language_for_extension(ext) or "generic"
            ).lower()
            parsed = self.parser.parse_file(f_node.path, content, language)
            parsed_files.append(parsed)

            if parsed.parser_used == "tree-sitter":
                ts_count += 1
            else:
                regex_count += 1

            if parsed.has_errors:
                error_count += 1

            all_symbols.extend(parsed.symbols)

            # Analyze risks
            raw_lines = content.splitlines()
            risks = risk_analyzer.analyze_file(parsed, raw_lines)
            all_risks.extend(risks)

            # Chunk large files
            chunks = self.chunker.chunk_file(parsed, raw_lines)
            all_chunks.extend(chunks)

        # Build dependency graph
        dep_graph = dep_analyzer.build_graph(parsed_files)

        # Detect architecture patterns
        architecture_findings = self.arch_detector.detect(known_files)

        parse_status = ParseStatus(
            tree_sitter_files=ts_count,
            regex_fallback_files=regex_count,
            parse_errors_count=error_count,
        )

        repo_name = repo_dir.name or "repository"
        return AnalysisResult(
            repo_name=repo_name,
            architecture=architecture_findings,
            dependency_graph=dep_graph,
            symbols=all_symbols,
            risk_signals=all_risks,
            chunks=all_chunks,
            parse_status=parse_status,
        )
