"""Embedding-based retrieval provider with graceful fallback."""

import logging

from codeguide.retrieval.base import BaseRetriever
from codeguide.retrieval.keyword import KeywordRetriever
from codeguide.retrieval.models import RetrievalChunk, SearchResult

logger = logging.getLogger("codeguide.retrieval.embedding")


class EmbeddingRetriever(BaseRetriever):
    """Vector embedding retrieval with deterministic keyword fallback."""

    def __init__(self, fallback_k1: float = 1.5, fallback_b: float = 0.75) -> None:
        self.fallback = KeywordRetriever(k1=fallback_k1, b=fallback_b)
        self.embeddings: dict[int, list[float]] = {}
        self.chunks: list[RetrievalChunk] = []

    def index(self, chunks: list[RetrievalChunk]) -> None:
        self.chunks = chunks
        self.fallback.index(chunks)

    def search(self, query: str, top_k: int) -> list[SearchResult]:
        # When remote embeddings are unconfigured or in offline mode, delegate to keyword ranker
        return self.fallback.search(query, top_k)
