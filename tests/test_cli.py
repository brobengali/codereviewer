"""Tests for CodeGuide Typer CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from codeguide.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CodeGuide:" in result.stdout
    assert "Defaults schema version: 1.0.0" in result.stdout


def test_cli_config_show() -> None:
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert '"model_name":' in result.stdout
    assert '"citation_format":' in result.stdout


def test_cli_config_validate_valid(tmp_path: Path) -> None:
    valid_file = tmp_path / "codeguide.toml"
    valid_file.write_text("[ui]\nverbose = true\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", str(valid_file)])
    assert result.exit_code == 0
    assert "Valid configuration" in result.stdout


def test_cli_config_validate_invalid(tmp_path: Path) -> None:
    invalid_file = tmp_path / "bad.toml"
    invalid_file.write_text("[llm]\nmax_tokens = 'not-an-int'\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", str(invalid_file)])
    assert result.exit_code == 1


def test_cli_analyze_with_model_override(tmp_path: Path) -> None:
    out_dir = tmp_path / "custom_out"
    result = runner.invoke(
        app,
        ["analyze", str(tmp_path), "--model", "custom-cli-model", "--output-dir", str(out_dir)],
    )
    assert result.exit_code == 0
    assert "Target repository:" in result.stdout
    assert "Configured model: custom-cli-model" in result.stdout
    assert "Generated documentation: ONBOARDING.md and index.html" in result.stdout
    assert (out_dir / "ONBOARDING.md").exists()
    assert (out_dir / "index.html").exists()


def test_cli_analyze_invalid_dir(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does_not_exist"
    result = runner.invoke(app, ["analyze", str(nonexistent)])
    assert result.exit_code == 1
    assert "Target repository path is not a directory" in result.stderr
