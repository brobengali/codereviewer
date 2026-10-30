"""Tests for codeguide ask and explain commands, retrieval, audience adaptation, and grounding."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codeguide.cli import app
from codeguide.config.loader import load_config
from codeguide.generator.grounding import CitationGrounder
from codeguide.llm.base import LLMProvider
from codeguide.llm.models import AnswerCitation, AskResponse, ExplainResponse
from codeguide.redactor.engine import SecretRedactor
from codeguide.retrieval.chunker import RepositoryChunker
from codeguide.retrieval.keyword import KeywordRetriever
from codeguide.retrieval.models import RetrievalChunk
from codeguide.scanner.models import DetectedLanguage, FileNode, KeyDocument, ScanResult

runner = CliRunner()


@pytest.fixture
def sample_ask_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# OrderService\nHandles order dispatch.", encoding="utf-8")
    src = repo / "src"
    src.mkdir()
    (src / "order.py").write_text(
        "class OrderProcessor:\n"
        "    def process_order(self, order_id: str) -> bool:\n"
        "        api_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        "        return True\n",
        encoding="utf-8",
    )
    return repo


# --- 1. Retrieval Engine and BM25 Tests ---


def test_keyword_retriever_ranks_by_relevance() -> None:
    chunks = [
        RetrievalChunk(
            file_path="src/order.py",
            start_line=1,
            end_line=4,
            content=(
                "class OrderProcessor:\n    def process_order(self, order_id):\n        return True"
            ),
            symbol_name="OrderProcessor",
        ),
        RetrievalChunk(
            file_path="src/user.py",
            start_line=1,
            end_line=4,
            content="class UserAuth:\n    def authenticate(self, username):\n        return False",
            symbol_name="UserAuth",
        ),
    ]

    retriever = KeywordRetriever()
    retriever.index(chunks)

    results = retriever.search("process order", top_k=2)
    assert len(results) > 0
    assert results[0].chunk.file_path == "src/order.py"
    assert results[0].chunk.symbol_name == "OrderProcessor"


def test_keyword_retriever_elevates_exact_symbol_match() -> None:
    chunks = [
        RetrievalChunk(
            file_path="src/auth.py",
            start_line=1,
            end_line=5,
            content="class TokenValidator:\n    pass",
            symbol_name="TokenValidator",
        ),
        RetrievalChunk(
            file_path="src/misc.py",
            start_line=1,
            end_line=5,
            content="def helper():\n    # calls token validator in comment\n    pass",
            symbol_name="helper",
        ),
    ]

    retriever = KeywordRetriever()
    retriever.index(chunks)

    results = retriever.search("TokenValidator", top_k=2)
    assert len(results) > 0
    assert results[0].chunk.symbol_name == "TokenValidator"


def test_keyword_retriever_nonexistent_query_returns_empty() -> None:
    chunks = [
        RetrievalChunk(
            file_path="src/app.py",
            start_line=1,
            end_line=3,
            content="def main(): pass",
        )
    ]
    retriever = KeywordRetriever()
    retriever.index(chunks)

    results = retriever.search("quantum_cryptography_blockchain", top_k=5)
    assert len(results) == 0


# --- 2. Retrieval Over Redacted Content Tests ---


def test_retrieval_chunks_built_on_redacted_content(sample_ask_repo: Path) -> None:
    cfg = load_config()
    raw_scan = ScanResult(
        repo_name="repo",
        repo_path=str(sample_ask_repo),
        total_files=2,
        total_lines=6,
        total_size_bytes=200,
        languages=[DetectedLanguage(name="Python", files_count=1, lines_count=4, percentage=100.0)],
        frameworks=[],
        package_managers=[],
        test_tools=[],
        entry_points=[],
        routes=[],
        db_models=[],
        env_vars=[],
        file_tree=FileNode(
            path="repo",
            is_dir=True,
            line_count=6,
            size_bytes=200,
            importance_score=1.0,
            language=None,
            children=[
                FileNode(
                    path="src/order.py",
                    is_dir=False,
                    line_count=4,
                    size_bytes=150,
                    importance_score=1.0,
                    language="Python",
                )
            ],
        ),
        documents=[
            KeyDocument(
                path="README.md",
                category="documentation",
                content="# OrderService\nHandles order dispatch.",
                line_count=2,
            )
        ],
    )

    redactor = SecretRedactor.load(cfg)
    sanitized_scan, _ = redactor.redact_scan_result(raw_scan)

    chunker = RepositoryChunker(cfg)
    chunks = chunker.build_chunks(sample_ask_repo, sanitized_scan)

    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    for chunk in chunks:
        assert raw_secret not in chunk.content
        assert raw_secret not in chunk.file_path


# --- 3. Grounding Pass for Ask & Explain Tests ---


def test_grounding_ask_valid_citations_retained(sample_ask_repo: Path) -> None:
    grounder = CitationGrounder(sample_ask_repo)
    resp = AskResponse(
        answer="OrderProcessor handles order execution.",
        evidence_found=True,
        citations=[AnswerCitation(path="src/order.py", start_line=1, end_line=2)],
        follow_up_questions=["How are errors handled in process_order?"],
    )

    grounded = grounder.ground_ask_response(resp)
    assert grounded.evidence_found is True
    assert grounded.answer == "OrderProcessor handles order execution."
    assert len(grounded.citations) == 1
    assert grounded.citations[0].path == "src/order.py"


def test_grounding_ask_missing_evidence_returns_unclear(sample_ask_repo: Path) -> None:
    grounder = CitationGrounder(sample_ask_repo)
    resp = AskResponse(
        answer="Bitcoin mining is not configured.",
        evidence_found=False,
        citations=[],
        follow_up_questions=[],
    )

    grounded = grounder.ground_ask_response(resp)
    assert grounded.evidence_found is False
    assert grounded.answer == "unclear"
    assert len(grounded.citations) == 0


def test_grounding_ask_invalid_line_citations_revert_to_unclear(sample_ask_repo: Path) -> None:
    grounder = CitationGrounder(sample_ask_repo)
    # Line 9999 is outside src/order.py (which has only 4 lines)
    resp = AskResponse(
        answer="OrderProcessor is defined here.",
        evidence_found=True,
        citations=[AnswerCitation(path="src/order.py", start_line=9999, end_line=9999)],
        follow_up_questions=[],
    )

    grounded = grounder.ground_ask_response(resp)
    assert grounded.evidence_found is False
    assert grounded.answer == "unclear"
    assert len(grounded.citations) == 0


def test_grounding_explain_audience_adaptation(sample_ask_repo: Path) -> None:
    grounder = CitationGrounder(sample_ask_repo)
    resp = ExplainResponse(
        target="OrderProcessor",
        audience_level="senior",
        summary="Processor encapsulation for order events.",
        explanation="OrderProcessor defines a bounded execution contract.",
        evidence_found=True,
        citations=[AnswerCitation(path="src/order.py", start_line=1, end_line=2)],
        follow_up_questions=["What is the concurrency model?"],
    )

    grounded = grounder.ground_explain_response(resp)
    assert grounded.evidence_found is True
    assert grounded.audience_level == "senior"
    assert grounded.summary == "Processor encapsulation for order events."
    assert len(grounded.citations) == 1


def test_grounding_explain_nonexistent_symbol_returns_unclear(sample_ask_repo: Path) -> None:
    grounder = CitationGrounder(sample_ask_repo)
    resp = ExplainResponse(
        target="QuantumCryptoEngine",
        audience_level="junior",
        summary="Quantum cryptographic engine.",
        explanation="Handles quantum encryption.",
        evidence_found=True,
        # Citations point to nonexistent file
        citations=[AnswerCitation(path="src/quantum.py", start_line=1, end_line=5)],
        follow_up_questions=[],
    )

    grounded = grounder.ground_explain_response(resp)
    assert grounded.evidence_found is False
    assert grounded.summary == "unclear"
    assert grounded.explanation == "unclear"
    assert len(grounded.citations) == 0


# --- 4. CLI Dry-Run and Boundary Token Tests ---


def test_cli_ask_dry_run_contains_boundary_and_schema(sample_ask_repo: Path) -> None:
    result = runner.invoke(
        app,
        ["ask", "How does OrderProcessor work?", "--repo", str(sample_ask_repo), "--dry-run"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "user_prompt" in payload
    assert "system_prompt" in payload
    assert "boundary_token" in payload
    assert f"<<<DATA_BLOCK_{payload['boundary_token']}>>>" in payload["user_prompt"]
    assert "OrderProcessor" in payload["user_prompt"]


def test_cli_explain_dry_run_adapts_to_audience(sample_ask_repo: Path) -> None:
    result_jr = runner.invoke(
        app,
        [
            "explain",
            "OrderProcessor",
            "--repo",
            str(sample_ask_repo),
            "--audience",
            "junior",
            "--dry-run",
        ],
    )
    assert result_jr.exit_code == 0
    payload_jr = json.loads(result_jr.stdout)
    assert "Audience level: junior" in payload_jr["user_prompt"]

    result_sr = runner.invoke(
        app,
        [
            "explain",
            "OrderProcessor",
            "--repo",
            str(sample_ask_repo),
            "--audience",
            "senior",
            "--dry-run",
        ],
    )
    assert result_sr.exit_code == 0
    payload_sr = json.loads(result_sr.stdout)
    assert "Audience level: senior" in payload_sr["user_prompt"]


def test_cli_explain_rejects_unsupported_audience(sample_ask_repo: Path) -> None:
    result = runner.invoke(
        app,
        ["explain", "OrderProcessor", "--repo", str(sample_ask_repo), "--audience", "expert_ninja"],
    )
    assert result.exit_code == 1
    assert "Unsupported audience level" in result.stderr


# --- 5. End-to-End Ask & Explain CLI Tests with Mock Provider ---


class MockLLMProvider(LLMProvider):
    def __init__(self, response_data: dict) -> None:
        self.response_data = response_data
        self.last_prompt = ""

    def generate(
        self,
        prompt: str,
        schema: type,
        system_instruction: str | None = None,
    ) -> dict:
        self.last_prompt = prompt
        return self.response_data


def test_cli_ask_e2e_with_grounded_answer(
    sample_ask_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_data = {
        "answer": "OrderProcessor is the core domain class handling order execution.",
        "evidence_found": True,
        "citations": [{"path": "src/order.py", "start_line": 1, "end_line": 2}],
        "follow_up_questions": ["What exceptions are raised by process_order?"],
    }
    mock_prov = MockLLMProvider(mock_data)
    monkeypatch.setattr("codeguide.cli.LocalProvider", lambda *args, **kwargs: mock_prov)

    result = runner.invoke(
        app,
        ["ask", "What is OrderProcessor?", "--repo", str(sample_ask_repo), "--offline"],
    )
    assert result.exit_code == 0
    assert "Question: What is OrderProcessor?" in result.stdout
    assert "Answer: OrderProcessor is the core domain class" in result.stdout
    assert "Citations:" in result.stdout
    assert "src/order.py:1-2" in result.stdout
    assert "Suggested Follow-ups:" in result.stdout
    assert "What exceptions are raised by process_order?" in result.stdout


def test_cli_explain_e2e_with_grounded_answer(
    sample_ask_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_data = {
        "target": "OrderProcessor",
        "audience_level": "mid",
        "summary": "Core processor class for orders.",
        "explanation": "OrderProcessor handles order execution with validation.",
        "evidence_found": True,
        "citations": [{"path": "src/order.py", "start_line": 1, "end_line": 2}],
        "follow_up_questions": ["How are order events dispatched?"],
    }
    mock_prov = MockLLMProvider(mock_data)
    monkeypatch.setattr("codeguide.cli.LocalProvider", lambda *args, **kwargs: mock_prov)

    result = runner.invoke(
        app,
        [
            "explain",
            "OrderProcessor",
            "--repo",
            str(sample_ask_repo),
            "--audience",
            "mid",
            "--offline",
        ],
    )
    assert result.exit_code == 0
    assert "Target: OrderProcessor (Audience: mid)" in result.stdout
    assert "Core processor class for orders." in result.stdout
    assert "Citations:" in result.stdout
    assert "src/order.py:1-2" in result.stdout
    assert "Suggested Follow-ups:" in result.stdout
