"""Tests for documentation and codebase slop checkers."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from codeguide.cli import app
from codeguide.config.loader import load_config
from codeguide.slop.code_checker import CodeSlopChecker
from codeguide.slop.doc_checker import DocSlopChecker

runner = CliRunner()


@pytest.fixture
def sample_grounding_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "test_repo"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "class Application:\n"
        "    def start(self):\n"
        "        return True\n"
        "    def run(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        "# TestApp\n"
        "A verifiable application for testing slop checking.\n"
        "Main entry point is in src/app.py.\n",
        encoding="utf-8",
    )
    return repo


def test_sloppy_fixture_doc_triggers_all_categories(sample_grounding_repo: Path) -> None:
    cfg = load_config()
    checker = DocSlopChecker(cfg, repo_path=sample_grounding_repo)

    # Document intentionally triggering every single violation category:
    # 1. banned_opener: "In today's fast-paced world, ..."
    # 2. banned_phrase: "... seamless integration ..."
    # 3. missing_citation: A sentence with no citation and no unclear marker
    # 4. invalid_citation (missing file): points to nonexistent_file.py
    # 5. invalid_citation (out-of-range line): points to src/app.py:9999
    # 6. low_specificity: vague generic sentence lacking repo identifiers or citations
    # 7. repetition: near-duplicate sentences
    # 8. sentence_length: sentence longer than max_sentence_length (35 words)
    long_sentence = (
        "This software architecture is carefully divided into several distinct components "
        "that collaborate with various independent submodules across the system to ensure "
        "that every incoming request is processed cleanly through the execution pipeline "
        "without unexpected failures or throughput degradation during peak operational workloads."
    )

    sloppy_markdown = f"""# Sloppy Documentation

In today's fast-paced world, software systems require seamless integration across layers.
The system handles logic properly.
The system handles logic properly.
The core service is configured in nonexistent_file.py:10-20.
Application lifecycle is managed in src/app.py:9999.
{long_sentence}
In conclusion, the platform delivers best practices.
"""

    res = checker.lint_text(sloppy_markdown, filename="sloppy.md")

    assert not res.passed
    assert res.slop_score > 0.0

    categories = {v.category for v in res.violations}

    # Verify every required category is triggered
    assert "banned_opener" in categories
    assert "banned_phrase" in categories
    assert "missing_citation" in categories
    assert "invalid_citation" in categories
    assert "low_specificity" in categories
    assert "repetition" in categories
    assert "sentence_length" in categories


def test_good_fixture_doc_passes_cleanly(sample_grounding_repo: Path) -> None:
    cfg = load_config()
    checker = DocSlopChecker(cfg, repo_path=sample_grounding_repo)

    good_markdown = """# Architecture Overview

The `Application` class defines the application entry point in `src/app.py:1-3`.
The runtime loop is initiated by calling `start()` method in `src/app.py:2-3`.
System deployment configuration steps remain unclear.
Project metadata is documented in `README.md:1-3`.
"""

    res = checker.lint_text(good_markdown, filename="good.md")

    assert res.passed
    assert res.slop_score == 0.0
    assert len(res.violations) == 0


def test_code_slop_catches_dead_function_and_restating_comment(tmp_path: Path) -> None:
    cfg = load_config()
    code_dir = tmp_path / "code_repo"
    code_dir.mkdir()

    # Planted dead function and restating comment
    (code_dir / "worker.py").write_text(
        "def live_task():\n"
        "    return 1\n\n"
        "# increment counter\n"
        "counter += 1\n\n"
        "def planted_dead_function():\n"
        "    return 999\n\n"
        "def caller():\n"
        "    return live_task()\n",
        encoding="utf-8",
    )

    checker = CodeSlopChecker(cfg, code_dir)
    res = checker.lint_repo()

    assert not res.passed
    assert res.slop_score >= 2.0

    categories = {v.category for v in res.violations}
    assert "dead_function" in categories
    assert "restating_comment" in categories

    dead_fns = [v.snippet for v in res.violations if v.category == "dead_function"]
    assert any("planted_dead_function" in fn for fn in dead_fns)


def test_code_slop_catches_stubs_and_bare_excepts(tmp_path: Path) -> None:
    cfg = load_config()
    code_dir = tmp_path / "stubs_repo"
    code_dir.mkdir()

    (code_dir / "stub.py").write_text(
        "def empty_function():\n"
        "    pass\n\n"
        "def risky_operation():\n"
        "    try:\n"
        "        x = 1\n"
        "    except:\n"
        "        x = 0\n"
        "    return x\n",
        encoding="utf-8",
    )

    checker = CodeSlopChecker(cfg, code_dir)
    res = checker.lint_repo()

    assert not res.passed
    categories = {v.category for v in res.violations}
    assert "stub_body" in categories
    assert "bare_except" in categories


def test_cli_lint_docs_fails_on_sloppy_and_passes_on_good(
    sample_grounding_repo: Path, tmp_path: Path
) -> None:
    sloppy_file = tmp_path / "bad.md"
    sloppy_file.write_text(
        "# Title\n\nIn today's fast-paced world, software delivers seamless integration.\n",
        encoding="utf-8",
    )

    good_file = tmp_path / "clean.md"
    good_file.write_text(
        "# Clean Document\n\nThe `Application` class is located in `src/app.py:1-3`.\n",
        encoding="utf-8",
    )

    # Sloppy document fails with exit code 1
    res_bad = runner.invoke(
        app,
        ["lint-docs", str(sloppy_file), "--repo", str(sample_grounding_repo)],
    )
    assert res_bad.exit_code == 1
    assert "FAILED" in res_bad.output

    # Good document passes with exit code 0
    res_good = runner.invoke(
        app,
        ["lint-docs", str(good_file), "--repo", str(sample_grounding_repo)],
    )
    assert res_good.exit_code == 0
    assert "PASSED" in res_good.output


def test_cli_lint_code_fails_on_slop_repo(tmp_path: Path) -> None:
    slop_repo = tmp_path / "slop_repo"
    slop_repo.mkdir()
    (slop_repo / "script.py").write_text(
        "# return True\nreturn True\n\ndef uncalled_dead():\n    return 10\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["lint-code", str(slop_repo)])
    assert res.exit_code == 1
    assert "FAILED" in res.output
