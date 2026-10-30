"""BM25 keyword retrieval engine for code chunks."""

import collections
import math
import re

from codeguide.retrieval.base import BaseRetriever
from codeguide.retrieval.models import RetrievalChunk, SearchResult

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_]{2,}")


def tokenize(text: str) -> list[str]:
    """Extract normalized alphanumeric tokens from text."""
    return [t.lower() for t in TOKEN_PATTERN.findall(text)]


class KeywordRetriever(BaseRetriever):
    """Pure-Python BM25 ranker indexing chunks without external dependencies."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.chunks: list[RetrievalChunk] = []
        self.doc_lengths: list[int] = []
        self.avg_doc_length: float = 0.0
        self.inverted_index: dict[str, list[tuple[int, int]]] = collections.defaultdict(list)
        self.doc_count: int = 0

    def index(self, chunks: list[RetrievalChunk]) -> None:
        self.chunks = chunks
        self.doc_count = len(chunks)
        self.doc_lengths = []
        self.inverted_index.clear()

        if self.doc_count == 0:
            self.avg_doc_length = 0.0
            return

        total_length = 0
        for idx, chunk in enumerate(chunks):
            # Include content, file path, and symbol name in tokenized document
            path_tokens = tokenize(chunk.file_path)
            sym_tokens = tokenize(chunk.symbol_name or "")
            content_tokens = tokenize(chunk.content)
            all_tokens = path_tokens + sym_tokens + content_tokens

            doc_len = len(all_tokens)
            self.doc_lengths.append(doc_len)
            total_length += doc_len

            term_counts = collections.Counter(all_tokens)
            for term, count in term_counts.items():
                self.inverted_index[term].append((idx, count))

        self.avg_doc_length = total_length / self.doc_count

    def search(self, query: str, top_k: int) -> list[SearchResult]:
        if not self.chunks or self.doc_count == 0 or not query.strip():
            return []

        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        scores: dict[int, float] = collections.defaultdict(float)
        query_set = set(query_tokens)

        for token in query_tokens:
            postings = self.inverted_index.get(token, [])
            if not postings:
                continue

            df = len(postings)
            idf = math.log(1.0 + (self.doc_count - df + 0.5) / (df + 0.5))

            for doc_idx, tf in postings:
                doc_len = self.doc_lengths[doc_idx]
                norm = 1.0 - self.b + self.b * (doc_len / max(self.avg_doc_length, 1.0))
                denom = tf + self.k1 * norm
                score = idf * (tf * (self.k1 + 1.0)) / max(denom, 1e-6)
                scores[doc_idx] += score

        # Apply exact match bonuses for symbol and file path
        results: list[SearchResult] = []
        for doc_idx, score in scores.items():
            chunk = self.chunks[doc_idx]
            final_score = score

            if chunk.symbol_name and chunk.symbol_name.lower() in query_set:
                final_score *= 1.5

            path_tokens = set(tokenize(chunk.file_path))
            matched_path_tokens = path_tokens.intersection(query_set)
            if matched_path_tokens:
                final_score += 0.5 * len(matched_path_tokens)

            results.append(SearchResult(chunk=chunk, score=final_score))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]
