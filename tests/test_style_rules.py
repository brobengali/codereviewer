"""Tests verifying style rules configuration, overridability, and absence of hardcoded lists."""

import ast
import tomllib
from pathlib import Path

from codeguide.config.loader import load_config


def test_style_rules_file_content() -> None:
    data_dir = Path(__file__).resolve().parent.parent / "src" / "codeguide" / "data"
    style_file = data_dir / "style_rules.toml"
    assert style_file.is_file()

    with style_file.open("rb") as f:
        data = tomllib.load(f)

    assert "banned_phrases" in data
    assert "banned_openers" in data
    assert "vague_words" in data
    assert "rules" in data
    assert "max_sentence_length" in data["rules"]
    assert len(data["banned_phrases"]["phrases"]) > 0
    assert len(data["banned_openers"]["openers"]) > 0
    assert len(data["vague_words"]["words"]) > 0


def test_style_config_loaded_from_defaults() -> None:
    cfg = load_config()
    assert cfg.style.max_sentence_length == 35
    assert "robust" in cfg.style.vague_words
    assert "in conclusion" in cfg.style.banned_phrases
    assert "this comprehensive guide" in cfg.style.banned_openers


def test_style_config_overridable_via_file(tmp_path: Path) -> None:
    custom_config = tmp_path / "codeguide.toml"
    custom_config.write_text(
        """
[style]
max_sentence_length = 50
vague_words = ["custom_vague_term"]
""",
        encoding="utf-8",
    )

    cfg = load_config(config_path=custom_config, env={})
    assert cfg.style.max_sentence_length == 50
    assert cfg.style.vague_words == ["custom_vague_term"]
    # Sibling lists remain intact from defaults
    assert "in conclusion" in cfg.style.banned_phrases


def test_style_config_overridable_via_env() -> None:
    env = {
        "CODEGUIDE_STYLE__MAX_SENTENCE_LENGTH": "42",
        "CODEGUIDE_STYLE__VAGUE_WORDS": '["fluffy", "handwavy"]',
    }
    cfg = load_config(env=env)
    assert cfg.style.max_sentence_length == 42
    assert cfg.style.vague_words == ["fluffy", "handwavy"]


def test_no_banned_word_lists_in_python_source() -> None:
    src_dir = Path(__file__).resolve().parent.parent / "src" / "codeguide"
    sample_banned = ["robust", "seamless", "delve", "cutting-edge"]

    for py_file in src_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
                # Inspect string literals in collections
                elements = [
                    elt.value.lower()
                    for elt in node.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
                for banned in sample_banned:
                    err = f"Hardcoded list with '{banned}' in {py_file.name}:{node.lineno}"
                    assert banned not in elements, err
