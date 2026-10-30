"""Transforms scanned repository contents and analysis AST chunks into retrieval units."""

import logging
from pathlib import Path
from typing import Any

from codeguide.analyzer.models import AnalysisResult
from codeguide.config.models import AppConfig
from codeguide.redactor.engine import SecretRedactor
from codeguide.retrieval.models import RetrievalChunk
from codeguide.scanner.models import ScanResult

logger = logging.getLogger("codeguide.retrieval.chunker")


class RepositoryChunker:
    """Builds line-bounded retrieval chunks over sanitized repository files."""

    def __init__(self, config: AppConfig, redactor: SecretRedactor | None = None) -> None:
        self.config = config
        self.redactor = redactor or SecretRedactor.load(config)
        self.max_chunk_lines = config.analysis.chunking.max_chunk_lines
        self.overlap = config.analysis.chunking.chunk_overlap_lines
        self.min_chunk_lines = config.analysis.chunking.min_chunk_lines

    def _chunk_lines(
        self,
        file_path: str,
        lines: list[str],
        symbol_name: str | None = None,
    ) -> list[RetrievalChunk]:
        chunks: list[RetrievalChunk] = []
        total_lines = len(lines)
        if total_lines == 0:
            return chunks

        if total_lines <= self.max_chunk_lines:
            return [
                RetrievalChunk(
                    file_path=file_path,
                    start_line=1,
                    end_line=total_lines,
                    content="\n".join(lines),
                    symbol_name=symbol_name,
                )
            ]

        step = max(self.max_chunk_lines - self.overlap, 1)
        start = 0
        while start < total_lines:
            end = min(start + self.max_chunk_lines, total_lines)
            chunk_content = "\n".join(lines[start:end])
            chunks.append(
                RetrievalChunk(
                    file_path=file_path,
                    start_line=start + 1,
                    end_line=end,
                    content=chunk_content,
                    symbol_name=symbol_name,
                )
            )
            if end >= total_lines:
                break
            start += step

        return chunks

    def build_chunks(
        self,
        repo_root: Path,
        scan_result: ScanResult,
        analysis_result: AnalysisResult | None = None,
    ) -> list[RetrievalChunk]:
        retrieval_chunks: list[RetrievalChunk] = []
        indexed_files: set[str] = set()

        # 1. Use AST code chunks if available from analysis
        if analysis_result and analysis_result.chunks:
            for c in analysis_result.chunks:
                clean = self.redactor.redact_text(c.content).clean_text
                retrieval_chunks.append(
                    RetrievalChunk(
                        file_path=c.file_path,
                        start_line=c.start_line,
                        end_line=c.end_line,
                        content=clean,
                        symbol_name=c.parent_symbol,
                    )
                )
                indexed_files.add(c.file_path)

        # 2. Chunk documents (README, CI configs, manifests)
        for doc in scan_result.documents:
            if doc.path not in indexed_files:
                clean = self.redactor.redact_text(doc.content).clean_text
                doc_lines = clean.splitlines()
                retrieval_chunks.extend(self._chunk_lines(doc.path, doc_lines))
                indexed_files.add(doc.path)

        # 3. Chunk any remaining scanned files
        def traverse_tree(node: Any) -> None:
            if not node.is_dir and node.path not in indexed_files:
                ext = Path(node.path).suffix.lower()
                if ext not in self.config.analysis.binary_extensions:
                    full_p = repo_root / node.path
                    if full_p.is_file():
                        try:
                            raw_text = full_p.read_text(encoding="utf-8", errors="replace")
                            clean = self.redactor.redact_text(raw_text).clean_text
                            lines = clean.splitlines()
                            retrieval_chunks.extend(self._chunk_lines(node.path, lines))
                            indexed_files.add(node.path)
                        except OSError as exc:
                            logger.debug("Failed reading file %s for chunking: %s", node.path, exc)
            for child in getattr(node, "children", []):
                traverse_tree(child)

        traverse_tree(scan_result.file_tree)
        return retrieval_chunks
