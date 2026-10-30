"""Semantic and line-bounded chunking strategy for large source files."""

from codeguide.analyzer.models import CodeChunk, ParsedFile
from codeguide.config.models import AppConfig


class FileChunker:
    """Partitions large files into bounded, overlapping chunks with line citations."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def chunk_file(
        self,
        parsed_file: ParsedFile,
        lines: list[str],
        force: bool = False,
    ) -> list[CodeChunk]:
        max_lines = self.config.analysis.chunking.max_chunk_lines
        overlap = self.config.analysis.chunking.chunk_overlap_lines
        total_lines = len(lines)

        if not force and total_lines <= max_lines:
            return []

        step = max(1, max_lines - overlap)
        chunks: list[CodeChunk] = []
        raw_windows: list[tuple[int, int]] = []

        start = 0
        while start < total_lines:
            end = min(start + max_lines, total_lines)
            raw_windows.append((start, end))
            if end >= total_lines:
                break
            start += step

        total_chunks = len(raw_windows)

        for idx, (w_start, w_end) in enumerate(raw_windows, start=1):
            chunk_content = "\n".join(lines[w_start:w_end])
            start_line = w_start + 1
            end_line = w_end

            # Find matching parent symbol covering this range
            parent_symbol: str | None = None
            for sym in parsed_file.symbols:
                s_start = sym.citation.start_line
                s_end = sym.citation.end_line
                if s_start <= start_line and s_end >= end_line:
                    parent_symbol = sym.name
                    break
                if s_start >= start_line and s_start <= end_line:
                    parent_symbol = sym.name
                    break

            chunks.append(
                CodeChunk(
                    file_path=parsed_file.file_path,
                    chunk_index=idx,
                    total_chunks=total_chunks,
                    start_line=start_line,
                    end_line=end_line,
                    content=chunk_content,
                    parent_symbol=parent_symbol,
                )
            )

        return chunks
