"""Abstract base class for retrieval strategies."""

from abc import ABC, abstractmethod

from codeguide.retrieval.models import RetrievalChunk, SearchResult


class BaseRetriever(ABC):
    """Abstract retrieval provider indexing chunks and searching by query."""

    @abstractmethod
    def index(self, chunks: list[RetrievalChunk]) -> None:
        """Index a collection of code chunks."""

    @abstractmethod
    def search(self, query: str, top_k: int) -> list[SearchResult]:
        """Search indexed chunks for most relevant candidates."""
