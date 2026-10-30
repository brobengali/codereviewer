"""Tests for repository code analyzer with Tree-Sitter AST and graph analysis."""

import json
from pathlib import Path

from codeguide.analyzer.architecture import ArchitectureDetector
from codeguide.analyzer.chunker import FileChunker
from codeguide.analyzer.dependency import DependencyAnalyzer
from codeguide.analyzer.engine import RepositoryAnalyzer
from codeguide.analyzer.grammars import GrammarRegistry
from codeguide.analyzer.models import ParsedFile
from codeguide.analyzer.parser import CodeParser
from codeguide.analyzer.risks import RiskAnalyzer
from codeguide.config.loader import load_config
from codeguide.scanner.scanner import RepositoryScanner


def test_tree_sitter_python_parser() -> None:
    cfg = load_config()
    registry = GrammarRegistry(cfg)
    parser = CodeParser(registry)

    code = """import os
from pathlib import Path
from .models import Item

class UserAccount:
    def get_id(self):
        return 1

def compute_total(a, b):
    return a + b
"""
    parsed = parser.parse_file("app/main.py", code, "python")
    assert parsed.parser_used == "tree-sitter"
    assert not parsed.has_errors
    assert parsed.lines_count == 10

    sym_names = [s.name for s in parsed.symbols]
    assert "UserAccount" in sym_names
    assert "compute_total" in sym_names

    user_cls = next(s for s in parsed.symbols if s.name == "UserAccount")
    assert user_cls.kind == "class"
    assert user_cls.citation.start_line == 5
    assert user_cls.citation.end_line == 7

    imp_sources = [imp.source for imp in parsed.imports]
    assert "os" in imp_sources
    assert "pathlib" in imp_sources
    assert ".models" in imp_sources

    rel_imp = next(imp for imp in parsed.imports if imp.source == ".models")
    assert rel_imp.is_relative


def test_tree_sitter_javascript_parser() -> None:
    cfg = load_config()
    registry = GrammarRegistry(cfg)
    parser = CodeParser(registry)

    code = """const express = require('express');
import { helper } from './utils';

class Server {
    start() {}
}

function runServer() {
    return true;
}
"""
    parsed = parser.parse_file("src/index.js", code, "javascript")
    assert parsed.parser_used == "tree-sitter"
    assert not parsed.has_errors

    sym_names = [s.name for s in parsed.symbols]
    assert "Server" in sym_names
    assert "runServer" in sym_names

    imp_sources = [imp.source for imp in parsed.imports]
    assert "express" in imp_sources
    assert "./utils" in imp_sources


def test_graceful_regex_fallback_when_grammar_missing() -> None:
    cfg = load_config()
    registry = GrammarRegistry(cfg)
    parser = CodeParser(registry)

    # Elixir / Ruby style syntax with no tree-sitter grammar registered
    code = """require 'logger'
def calculate_score(val)
  val * 10
end

class AccountManager
end
"""
    parsed = parser.parse_file("lib/account.rb", code, "ruby")
    assert parsed.parser_used == "regex"
    assert not parsed.has_errors

    sym_names = [s.name for s in parsed.symbols]
    assert "calculate_score" in sym_names
    assert "AccountManager" in sym_names
    assert any(imp.source == "logger" for imp in parsed.imports)


def test_parse_failure_case() -> None:
    cfg = load_config()
    registry = GrammarRegistry(cfg)
    parser = CodeParser(registry)

    broken_code = """def valid_fn():
    return True

def broken_syntax(:
    invalid
"""
    parsed = parser.parse_file("app/broken.py", broken_code, "python")
    assert parsed.parser_used == "tree-sitter"
    assert parsed.has_errors
    assert parsed.error_line == 4

    risk_analyzer = RiskAnalyzer(cfg, ["app/broken.py"])
    risks = risk_analyzer.analyze_file(parsed, broken_code.splitlines())

    parse_risk = next((r for r in risks if r.signal_type == "parse_failure"), None)
    assert parse_risk is not None
    assert parse_risk.citation.start_line == 4
    assert parse_risk.severity == "warning"


def test_dependency_graph_core_and_leaf_modules() -> None:
    cfg = load_config()
    known_files = [
        "app/core/base.py",
        "app/services/user_service.py",
        "app/services/order_service.py",
        "app/cli.py",
    ]
    dep_analyzer = DependencyAnalyzer(cfg, known_files)

    # base.py imported by user_service and order_service
    # cli.py imports user_service, imported by none
    p_base = ParsedFile(
        file_path="app/core/base.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[],
        lines_count=20,
    )
    p_user = ParsedFile(
        file_path="app/services/user_service.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[
            {
                "source": "../core/base",
                "imported_symbols": [],
                "is_relative": True,
                "citation": {
                    "file_path": "app/services/user_service.py",
                    "start_line": 1,
                    "end_line": 1,
                    "snippet": "import",
                },
            }
        ],
        lines_count=30,
    )
    p_order = ParsedFile(
        file_path="app/services/order_service.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[
            {
                "source": "../core/base",
                "imported_symbols": [],
                "is_relative": True,
                "citation": {
                    "file_path": "app/services/order_service.py",
                    "start_line": 1,
                    "end_line": 1,
                    "snippet": "import",
                },
            }
        ],
        lines_count=30,
    )
    p_cli = ParsedFile(
        file_path="app/cli.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[
            {
                "source": "services/user_service",
                "imported_symbols": [],
                "is_relative": False,
                "citation": {
                    "file_path": "app/cli.py",
                    "start_line": 1,
                    "end_line": 1,
                    "snippet": "import",
                },
            }
        ],
        lines_count=15,
    )

    graph = dep_analyzer.build_graph([p_base, p_user, p_order, p_cli])
    assert "app/core/base.py" in graph.core_modules
    assert "app/cli.py" in graph.leaf_modules

    cli_node = next(n for n in graph.nodes if n.file_path == "app/cli.py")
    assert cli_node.leaf_type == "entry"


def test_circular_dependency_detection() -> None:
    cfg = load_config()
    known_files = ["app/alpha.py", "app/beta.py"]
    dep_analyzer = DependencyAnalyzer(cfg, known_files)

    p_a = ParsedFile(
        file_path="app/alpha.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[
            {
                "source": ".beta",
                "imported_symbols": [],
                "is_relative": True,
                "citation": {
                    "file_path": "app/alpha.py",
                    "start_line": 1,
                    "end_line": 1,
                    "snippet": "import .beta",
                },
            }
        ],
        lines_count=10,
    )
    p_b = ParsedFile(
        file_path="app/beta.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[
            {
                "source": ".alpha",
                "imported_symbols": [],
                "is_relative": True,
                "citation": {
                    "file_path": "app/beta.py",
                    "start_line": 1,
                    "end_line": 1,
                    "snippet": "import .alpha",
                },
            }
        ],
        lines_count=10,
    )

    graph = dep_analyzer.build_graph([p_a, p_b])
    assert len(graph.circular_dependencies) > 0
    cycle = graph.circular_dependencies[0]
    assert "app/alpha.py" in cycle.cycle
    assert "app/beta.py" in cycle.cycle
    assert len(cycle.citations) >= 2


def test_architecture_pattern_detection() -> None:
    cfg = load_config()
    detector = ArchitectureDetector(cfg)

    # MVC repository structure
    mvc_files = [
        "app/controllers/user_controller.py",
        "app/models/user.py",
        "app/views/user_view.py",
    ]
    mvc_findings = detector.detect(mvc_files)
    assert any(f.pattern_id == "mvc" for f in mvc_findings)

    # Layered architecture structure
    layered_files = [
        "src/api/routes.py",
        "src/services/auth_service.py",
        "src/repositories/user_repo.py",
    ]
    layered_findings = detector.detect(layered_files)
    assert any(f.pattern_id == "layered" for f in layered_findings)

    # Monorepo structure
    monorepo_files = [
        "packages/core/index.js",
        "packages/ui/index.js",
        "pnpm-workspace.yaml",
    ]
    monorepo_findings = detector.detect(monorepo_files)
    assert any(f.pattern_id == "monorepo" for f in monorepo_findings)

    # Microservices structure
    microservices_files = [
        "services/auth/Dockerfile",
        "services/billing/Dockerfile",
        "docker-compose.yml",
    ]
    microservices_findings = detector.detect(microservices_files)
    assert any(f.pattern_id == "microservices" for f in microservices_findings)

    # Monolith structure
    monolith_files = [
        "src/main.py",
        "src/utils.py",
        "src/config.py",
    ]
    monolith_findings = detector.detect(monolith_files)
    assert any(f.pattern_id == "monolith" for f in monolith_findings)


def test_risk_signals_detection() -> None:
    cfg = load_config()
    known_files = ["app/huge.py", "app/untested.py", "app/todos.py"]
    risk_analyzer = RiskAnalyzer(cfg, known_files)

    # 1. Huge file (>500 lines)
    huge_lines = [f"line_{i} = {i}" for i in range(505)]
    p_huge = ParsedFile(
        file_path="app/huge.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[],
        lines_count=505,
    )
    huge_risks = risk_analyzer.analyze_file(p_huge, huge_lines)
    assert any(r.signal_type == "huge_file" for r in huge_risks)

    # 2. TODO/FIXME cluster
    todo_lines = [
        "# Normal line",
        "# TODO: refactor authentication",
        "# FIXME: memory leak on loop",
        "# HACK: temporary workaround",
        "# Normal line",
    ]
    p_todo = ParsedFile(
        file_path="app/todos.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[],
        lines_count=5,
    )
    todo_risks = risk_analyzer.analyze_file(p_todo, todo_lines)
    assert any(r.signal_type == "todo_cluster" for r in todo_risks)

    # 3. Untested source file
    p_untested = ParsedFile(
        file_path="app/untested.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[],
        lines_count=20,
    )
    untested_risks = risk_analyzer.analyze_file(p_untested, ["x = 1"])
    assert any(r.signal_type == "untested_file" for r in untested_risks)


def test_chunking_strategy() -> None:
    cfg = load_config()
    chunker = FileChunker(cfg)

    # Generate 150 lines (exceeds default max_chunk_lines=100)
    lines = [f"def function_{i}(): pass" for i in range(150)]
    p_file = ParsedFile(
        file_path="app/large.py",
        language="python",
        parser_used="tree-sitter",
        has_errors=False,
        symbols=[],
        imports=[],
        lines_count=150,
    )

    chunks = chunker.chunk_file(p_file, lines)
    assert len(chunks) >= 2
    assert chunks[0].chunk_index == 1
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 100
    assert chunks[1].chunk_index == 2
    assert chunks[1].start_line > 1
    assert chunks[1].end_line == 150


def test_end_to_end_analysis_result_typed_and_serializable(tmp_path: Path) -> None:
    cfg = load_config()
    repo_dir = tmp_path / "fixture_repo"
    repo_dir.mkdir()

    src_dir = repo_dir / "src"
    src_dir.mkdir()
    (src_dir / "database.py").write_text("class Database:\n    pass\n", encoding="utf-8")
    (src_dir / "service.py").write_text(
        "from .database import Database\n\ndef run_service():\n    return Database()\n",
        encoding="utf-8",
    )
    (repo_dir / "README.md").write_text("# Fixture Repo\nDoc overview.", encoding="utf-8")

    scanner = RepositoryScanner(repo_dir, cfg)
    scan_res = scanner.scan()

    analyzer = RepositoryAnalyzer(cfg)
    analysis_res = analyzer.analyze(repo_dir, scan_res)

    # Verify JSON serialization
    serialized = analysis_res.model_dump_json(indent=2)
    assert serialized is not None
    data = json.loads(serialized)

    assert data["repo_name"] == "fixture_repo"
    assert data["parse_status"]["tree_sitter_files"] >= 1
    assert len(data["symbols"]) >= 2

    # Verify all citations have valid file_path and line numbers
    for sym in analysis_res.symbols:
        assert sym.citation.file_path.startswith("src")
        assert sym.citation.start_line >= 1
        assert sym.citation.end_line >= sym.citation.start_line
