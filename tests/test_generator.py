"""Tests for documentation generation, grounding pass, and security defenses."""

from pathlib import Path

import pytest

from codeguide.analyzer.models import (
    AnalysisResult,
    ArchitectureFinding,
    DependencyGraph,
    DependencyNode,
    ParseStatus,
    SymbolDefinition,
)
from codeguide.config.loader import load_config
from codeguide.generator.engine import DocumentationGenerator
from codeguide.generator.grounding import CitationGrounder
from codeguide.generator.html_escaper import (
    escape_html_text,
    safe_json_embed,
    sanitize_markdown_text,
)
from codeguide.generator.mermaid import (
    build_mermaid_architecture,
    sanitize_node_id,
    sanitize_node_label,
)
from codeguide.generator.models import (
    FeatureFlow,
    FeatureFlowStep,
    FolderGuideItem,
    GlossaryTerm,
    GotchaItem,
    OnboardingContext,
    SetupStep,
    StarterTask,
    TechStackItem,
)
from codeguide.generator.writer import SafeOutputWriter, UnsafeOutputError
from codeguide.scanner.models import Citation, DetectedLanguage, FileNode, KeyDocument, ScanResult


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "test_repo"
    repo.mkdir()
    (repo / "README.md").write_text(
        "# TestApp\nA test application for data validation.", encoding="utf-8"
    )
    (repo / "pyproject.toml").write_text(
        "[project]\nname = 'testapp'\nversion = '0.1.0'", encoding="utf-8"
    )
    src = repo / "src"
    src.mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "app.py").write_text(
        "class Application:\n    def start(self):\n        pass\n",
        encoding="utf-8",
    )
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "def test_app():\n    assert True\n",
        encoding="utf-8",
    )
    return repo


@pytest.fixture
def mock_scan_and_analysis(sample_repo: Path) -> tuple[ScanResult, AnalysisResult]:
    scan = ScanResult(
        repo_name="test_repo",
        repo_path=str(sample_repo),
        total_files=5,
        total_lines=15,
        total_size_bytes=300,
        languages=[
            DetectedLanguage(name="Python", files_count=3, lines_count=10, percentage=100.0)
        ],
        frameworks=[],
        package_managers=[],
        test_tools=[],
        entry_points=[],
        routes=[],
        db_models=[],
        env_vars=[],
        file_tree=FileNode(
            path="test_repo",
            is_dir=True,
            line_count=15,
            size_bytes=300,
            importance_score=1.0,
            language=None,
            children=[
                FileNode(
                    path="src",
                    is_dir=True,
                    line_count=3,
                    size_bytes=50,
                    importance_score=1.0,
                    language=None,
                    children=[
                        FileNode(
                            path="src/app.py",
                            is_dir=False,
                            line_count=3,
                            size_bytes=50,
                            importance_score=1.0,
                            language="Python",
                        )
                    ],
                )
            ],
        ),
        documents=[
            KeyDocument(
                path="README.md",
                category="documentation",
                content="# TestApp\nA test application for data validation.",
                line_count=2,
            )
        ],
    )

    cit = Citation(
        file_path="src/app.py",
        start_line=1,
        end_line=3,
        snippet="class Application:\n    def start",
    )
    analysis = AnalysisResult(
        repo_name="test_repo",
        architecture=[
            ArchitectureFinding(
                pattern_id="layered",
                name="Layered Architecture",
                confidence=0.85,
                description="Separation of concerns into distinct layers.",
                evidence_paths=["src/app.py"],
                citations=[cit],
            )
        ],
        dependency_graph=DependencyGraph(
            nodes=[
                DependencyNode(
                    file_path="src/app.py",
                    in_degree=0,
                    out_degree=0,
                    is_core=True,
                    is_leaf=False,
                )
            ],
            edges=[],
            core_modules=["src/app.py"],
            leaf_modules=[],
            circular_dependencies=[],
        ),
        symbols=[
            SymbolDefinition(
                name="Application",
                kind="class",
                citation=cit,
            )
        ],
        risk_signals=[],
        chunks=[],
        parse_status=ParseStatus(tree_sitter_files=1, regex_fallback_files=0, parse_errors_count=0),
    )

    return scan, analysis


# --- 1. XSS and Injection Neutralization Tests ---


def test_escape_html_text_neutralizes_xss() -> None:
    payload = "<script>alert('XSS')</script>"
    escaped = escape_html_text(payload)
    assert "<script>" not in escaped
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" == escaped


def test_safe_json_embed_neutralizes_script_closing_tag() -> None:
    data = {"comment": "</script><script>alert('XSS')</script>"}
    embedded = safe_json_embed(data)
    assert "</script>" not in embedded
    assert "\\u003c/script\\u003e" in embedded


def test_sanitize_markdown_disarms_javascript_urls() -> None:
    md_payload = "[Click here](javascript:alert(1))"
    sanitized = sanitize_markdown_text(md_payload)
    assert "javascript:" not in sanitized
    assert "#blocked-scheme" in sanitized


def test_sanitize_markdown_escapes_raw_html() -> None:
    md_payload = "Normal text <img src=x onerror=alert(1)> more text"
    sanitized = sanitize_markdown_text(md_payload)
    assert "<img" not in sanitized
    assert "&lt;img src=x onerror=alert(1)&gt;" in sanitized


# --- 2. Mermaid Diagram Sanitization Tests ---


def test_mermaid_sanitize_node_id_is_alphanumeric() -> None:
    raw = "../src/app.py; drop table--"
    node_id = sanitize_node_id(raw)
    assert node_id.startswith("node_")
    assert ";" not in node_id
    assert "/" not in node_id
    assert " " not in node_id


def test_mermaid_sanitize_node_label_neutralizes_delimiters_and_directives() -> None:
    malicious = 'app"]; click evil "alert"; style evil fill:#f00;'
    sanitized = sanitize_node_label(malicious)
    assert '"]' not in sanitized
    assert "click " not in sanitized
    assert "_click_ " in sanitized or "&#59;" in sanitized


def test_mermaid_builder_neutralizes_injection() -> None:
    arch = 'Microservices; subgraph Evil ["Hack"]'
    modules = ['src/app.py"; click x "y', "src/db.py"]
    edges = [('src/app.py"; click x "y', "src/db.py")]
    diagram = build_mermaid_architecture(arch, modules, edges)

    assert "flowchart TD" in diagram
    assert '"; click' not in diagram
    assert "subgraph Evil" not in diagram


# --- 3. Safe Output Writer Tests ---


def test_safe_writer_writes_valid_file(tmp_path: Path) -> None:
    out_dir = tmp_path / "output"
    writer = SafeOutputWriter(out_dir)
    res_path = writer.write_artifact("test.txt", "safe content")
    assert res_path.exists()
    assert res_path.read_text(encoding="utf-8") == "safe content"


def test_safe_writer_rejects_path_traversal(tmp_path: Path) -> None:
    out_dir = tmp_path / "output"
    writer = SafeOutputWriter(out_dir)
    with pytest.raises(UnsafeOutputError):
        writer.write_artifact("../escape.txt", "evil")
    with pytest.raises(UnsafeOutputError):
        writer.write_artifact("sub/../../escape.txt", "evil")


def test_safe_writer_rejects_unsafe_filenames(tmp_path: Path) -> None:
    out_dir = tmp_path / "output"
    writer = SafeOutputWriter(out_dir)
    for bad_name in ("evil\0.txt", "file with space.txt", "test*file.txt", "..", "."):
        with pytest.raises(UnsafeOutputError):
            writer.write_artifact(bad_name, "content")


# --- 4. Post-Generation Grounding Pass Tests ---


def test_grounding_preserves_valid_citation(sample_repo: Path) -> None:
    grounder = CitationGrounder(sample_repo)
    # src/app.py has 3 lines; lines 1-2 define class Application
    valid, res = grounder.verify_citation("src/app.py", 1, 2, "Application class definition")
    assert valid is True
    assert res == "src/app.py:1-2"


def test_grounding_converts_missing_file_to_unclear(sample_repo: Path) -> None:
    grounder = CitationGrounder(sample_repo)
    valid, res = grounder.verify_citation("src/nonexistent.py", 1, 2, "Some claim")
    assert valid is False
    assert res == "unclear"


def test_grounding_converts_out_of_bounds_lines_to_unclear(sample_repo: Path) -> None:
    grounder = CitationGrounder(sample_repo)
    # src/app.py only has 3 lines
    valid, res = grounder.verify_citation("src/app.py", 10, 20, "Application")
    assert valid is False
    assert res == "unclear"


def test_grounding_converts_unimplausible_citation_to_unclear(sample_repo: Path) -> None:
    grounder = CitationGrounder(sample_repo)
    # line 1 is "class Application:" - does not contain "database" or "postgresql"
    valid, res = grounder.verify_citation(
        "src/app.py", 1, 1, "Postgresql database transaction pool"
    )
    assert valid is False
    assert res == "unclear"


def test_grounding_context_pass(sample_repo: Path) -> None:
    grounder = CitationGrounder(sample_repo)
    ctx = OnboardingContext(
        repo_name="test_repo",
        purpose="A test application for data validation.",
        purpose_citation="README.md:2",
        tech_stack=[
            TechStackItem(name="Python", category="Language", citation="src/nonexistent.py:1")
        ],
        architecture_name="Application Architecture",
        architecture_description="Application architecture",
        architecture_citation="src/app.py:1-2",
        mermaid_diagram="flowchart TD",
        folder_guide=[
            FolderGuideItem(path="src", purpose="Application logic", citation="src/app.py:1")
        ],
        feature_flows=[
            FeatureFlow(
                name="Start",
                description="Start app",
                steps=[
                    FeatureFlowStep(
                        order=1, description="Start Application", citation="src/app.py:2"
                    )
                ],
            )
        ],
        setup_steps=[
            SetupStep(
                step_number=1,
                instruction="Install dependencies via pyproject",
                citation="pyproject.toml:1",
            )
        ],
        glossary=[
            GlossaryTerm(term="Application", definition="App class", citation="src/app.py:1")
        ],
        inferred_conventions=["Conventions"],
        starter_tasks=[
            StarterTask(
                day=1,
                title="Test Application",
                description="Run tests",
                citation="tests/test_app.py:1",
            )
        ],
        gotchas=[
            GotchaItem(
                title="Risk",
                risk_type="Warning",
                explanation="Explanation",
                citation="src/app.py:1",
            )
        ],
    )

    grounded = grounder.ground_context(ctx)

    # Valid citations are verified
    assert grounded.purpose_citation == "README.md:2"
    assert grounded.architecture_citation == "src/app.py:1-2"
    assert grounded.glossary[0].citation == "src/app.py:1"
    # Invalid file citation is grounded to unclear
    assert grounded.tech_stack[0].citation == "unclear"


# --- 5. Full End-to-End Generator Pipeline Test ---


def test_documentation_generator_produces_artifacts(
    sample_repo: Path,
    mock_scan_and_analysis: tuple[ScanResult, AnalysisResult],
    tmp_path: Path,
) -> None:
    scan, analysis = mock_scan_and_analysis
    out_dir = tmp_path / "docs_output"

    cfg = load_config(cli_overrides={"paths": {"output_dir": str(out_dir)}})
    generator = DocumentationGenerator(cfg, sample_repo)
    artifacts = generator.generate(scan, analysis)

    assert "onboarding_md" in artifacts
    assert "interactive_html" in artifacts

    md_path = artifacts["onboarding_md"]
    html_path = artifacts["interactive_html"]

    assert md_path.exists()
    assert html_path.exists()

    md_content = md_path.read_text(encoding="utf-8")
    assert "# Onboarding Guide: test_repo" in md_content
    assert "## Purpose" in md_content
    assert "## Tech Stack" in md_content
    assert "## Architecture" in md_content
    assert "```mermaid" in md_content
    assert "## Folder Guide" in md_content
    assert "## Traced Feature Flows" in md_content
    assert "## Verified Setup Steps" in md_content
    assert "## Domain Glossary" in md_content
    assert "## Inferred Conventions" in md_content
    assert "## First-Week Starter Tasks" in md_content
    assert "## Gotchas and Hazards" in md_content

    html_content = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "default-src 'none'" in html_content
    assert "http://" not in html_content
    assert "https://" not in html_content
    assert "eval(" not in html_content
    assert "innerHTML" not in html_content
