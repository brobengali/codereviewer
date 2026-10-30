"""Retrieval engine orchestrating indexing, ranking, and target resolution."""

from pathlib import Path

from codeguide.analyzer.models import AnalysisResult
from codeguide.config.models import AppConfig
from codeguide.retrieval.base import BaseRetriever
from codeguide.retrieval.chunker import RepositoryChunker
from codeguide.retrieval.embedding import EmbeddingRetriever
from codeguide.retrieval.keyword import KeywordRetriever
from codeguide.retrieval.models import RetrievalChunk, SearchResult
from codeguide.scanner.models import ScanResult


class RetrievalEngine:
    """Manages repository chunking and relevance ranking."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.chunker = RepositoryChunker(config)
        self.chunks: list[RetrievalChunk] = []

        retriever_mode = config.retrieval.mode.lower()
        if retriever_mode == "embeddings":
            self.retriever: BaseRetriever = EmbeddingRetriever(
                fallback_k1=config.retrieval.bm25_k1,
                fallback_b=config.retrieval.bm25_b,
            )
        else:
            self.retriever = KeywordRetriever(
                k1=config.retrieval.bm25_k1,
                b=config.retrieval.bm25_b,
            )

    def index_repository(
        self,
        repo_root: Path,
        scan_result: ScanResult,
        analysis_result: AnalysisResult | None = None,
    ) -> int:
        """Chunk and index all sanitized repository files."""
        self.chunks = self.chunker.build_chunks(repo_root, scan_result, analysis_result)
        self.retriever.index(self.chunks)
        return len(self.chunks)

    def search(self, query: str, top_k: int | None = None) -> list[SearchResult]:
        """Search repository chunks by query text, filtering low-confidence results."""
        k = top_k or self.config.retrieval.top_k
        candidates = self.retriever.search(query, top_k=k * 2)

        # Filter by minimum score threshold
        filtered = [c for c in candidates if c.score >= self.config.retrieval.min_score_threshold]
        return filtered[:k]

    def search_target(self, target: str, top_k: int | None = None) -> list[SearchResult]:
        """Retrieve chunks directly referencing or implementing a target file or symbol."""
        k = top_k or self.config.retrieval.top_k
        clean_target = target.strip().replace("\\", "/").lower()

        exact_matches: list[SearchResult] = []
        for chunk in self.chunks:
            chunk_path = chunk.file_path.replace("\\", "/").lower()
            sym_name = (chunk.symbol_name or "").lower()

            if chunk_path.endswith(clean_target) or clean_target.endswith(chunk_path):
                exact_matches.append(SearchResult(chunk=chunk, score=10.0))
            elif sym_name == clean_target:
                exact_matches.append(SearchResult(chunk=chunk, score=9.0))
            elif sym_name and clean_target in sym_name:
                exact_matches.append(SearchResult(chunk=chunk, score=5.0))

        # Supplement with standard search
        query_results = self.search(target, top_k=k)
        seen_chunks = {
            (m.chunk.file_path, m.chunk.start_line, m.chunk.end_line) for m in exact_matches
        }

        for qr in query_results:
            key = (qr.chunk.file_path, qr.chunk.start_line, qr.chunk.end_line)
            if key not in seen_chunks:
                exact_matches.append(qr)
                seen_chunks.add(key)

        return exact_matches[:k]
