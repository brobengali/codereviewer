"""Architectural AST tests verifying ZERO hardcoded constants in source code."""

import ast
import tomllib
from pathlib import Path

FORBIDDEN_MODEL_PREFIXES = ("gemini", "gpt", "claude", "llama", "mistral")
FORBIDDEN_URL_PREFIXES = ("http://", "https://")


def get_src_python_files() -> list[Path]:
    root = Path(__file__).resolve().parent.parent / "src" / "codeguide"
    return list(root.rglob("*.py"))


def test_no_hardcoded_models_or_urls_in_source() -> None:
    py_files = get_src_python_files()
    assert len(py_files) > 0, "No source files discovered to inspect"

    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip().lower()
                for prefix in FORBIDDEN_MODEL_PREFIXES:
                    msg = f"Hardcoded model '{node.value}' in {file_path.name}:{node.lineno}"
                    assert not val.startswith(prefix), msg
                for prefix in FORBIDDEN_URL_PREFIXES:
                    msg = f"Hardcoded URL '{node.value}' in {file_path.name}:{node.lineno}"
                    assert not val.startswith(prefix), msg


def test_models_have_no_default_values() -> None:
    src_dir = Path(__file__).resolve().parent.parent / "src" / "codeguide"
    models_file = src_dir / "config" / "models.py"
    tree = ast.parse(models_file.read_text(encoding="utf-8"), filename=str(models_file))

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.endswith("Config"):
            for item in node.body:
                # model_config assignment is allowed; field defaults are forbidden
                if isinstance(item, ast.AnnAssign) and item.value is not None:
                    field_name = item.target.id if isinstance(item.target, ast.Name) else "?"
                    err_msg = (
                        f"Model {node.name} has default for field '{field_name}' "
                        f"at line {item.lineno}."
                    )
                    raise AssertionError(err_msg)


def test_data_files_exist_and_parseable() -> None:
    data_dir = Path(__file__).resolve().parent.parent / "src" / "codeguide" / "data"
    required_data_files = [
        "defaults.toml",
        "languages.toml",
        "entrypoints.toml",
        "architecture_rules.toml",
        "style_rules.toml",
        "messages.toml",
    ]

    for fname in required_data_files:
        fpath = data_dir / fname
        assert fpath.is_file(), f"Missing required data file: {fname}"
        with fpath.open("rb") as f:
            data = tomllib.load(f)
            assert isinstance(data, dict), f"Data file {fname} did not parse into a dictionary"
            has_ver = "version" in data or "meta" in data
            assert has_ver, f"Data file {fname} missing version metadata"

    rules_dir = data_dir / "rules"
    assert rules_dir.is_dir()
    for rule_file in rules_dir.glob("*.toml"):
        with rule_file.open("rb") as f:
            data = tomllib.load(f)
            assert isinstance(data, dict), f"Rule file {rule_file.name} invalid"
            assert "version" in data, f"Rule file {rule_file.name} missing version"


def test_templates_exist() -> None:
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    prompt_template = templates_dir / "prompts" / "analyze_repo.jinja2"
    output_template = templates_dir / "output" / "overview.md.jinja2"
    system_template = templates_dir / "prompts" / "system.jinja2"
    module_template = templates_dir / "prompts" / "module_summary.jinja2"
    folder_template = templates_dir / "prompts" / "folder_summary.jinja2"
    repo_template = templates_dir / "prompts" / "repo_overview.jinja2"

    assert prompt_template.is_file(), "Missing external prompt template"
    assert output_template.is_file(), "Missing external output template"
    assert system_template.is_file(), "Missing system prompt template"
    assert module_template.is_file(), "Missing module summary template"
    assert folder_template.is_file(), "Missing folder summary template"
    assert repo_template.is_file(), "Missing repo overview template"
