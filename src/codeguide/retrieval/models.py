"""Data models for retrieval chunks and search results."""

from pydantic import BaseModel, ConfigDict


class RetrievalChunk(BaseModel):
    """Line-bounded code segment indexed for semantic or keyword retrieval."""

    model_config = ConfigDict(extra="forbid")
    file_path: str
    start_line: int
    end_line: int
    content: str
    symbol_name: str | None = None


class SearchResult(BaseModel):
    """Ranked retrieval candidate with relevance score."""

    model_config = ConfigDict(extra="forbid")
    chunk: RetrievalChunk
    score: float
