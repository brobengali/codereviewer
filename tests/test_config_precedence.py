"""Tests verifying configuration precedence hierarchy."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from codeguide.config.loader import deep_merge, load_config, parse_env_overrides


def test_defaults_loaded_when_no_overrides(tmp_path: Path) -> None:
    # Baseline test: loads from packaged defaults.toml
    cfg = load_config(config_path=tmp_path / "nonexistent.toml", env={})
    assert cfg.meta.version == "1.0.0"
    assert cfg.llm.model_name == "gemini-1.5-flash"
    assert cfg.llm.request_timeout_seconds == 30.0
    assert cfg.citations.unclear_fallback == "unclear"


def test_file_config_overrides_defaults(tmp_path: Path) -> None:
    custom_config = tmp_path / "codeguide.toml"
    custom_config.write_text(
        """
[llm]
model_name = "test-file-model"
request_timeout_seconds = 45.0
""",
        encoding="utf-8",
    )

    cfg = load_config(config_path=custom_config, env={})
    assert cfg.llm.model_name == "test-file-model"
    assert cfg.llm.request_timeout_seconds == 45.0
    # Sibling field should remain intact from defaults
    assert cfg.llm.provider == "gemini"
    assert cfg.llm.max_retries == 3


def test_env_var_overrides_file_and_defaults(tmp_path: Path) -> None:
    custom_config = tmp_path / "codeguide.toml"
    custom_config.write_text(
        """
[llm]
model_name = "from-file"
""",
        encoding="utf-8",
    )

    env = {
        "CODEGUIDE_LLM__MODEL_NAME": "from-env",
        "CODEGUIDE_LLM__REQUEST_TIMEOUT_SECONDS": "60.0",
        "CODEGUIDE_ANALYSIS__MAX_FILES_COUNT": "999",
        "CODEGUIDE_UI__VERBOSE": "true",
    }

    cfg = load_config(config_path=custom_config, env=env)
    assert cfg.llm.model_name == "from-env"
    assert cfg.llm.request_timeout_seconds == 60.0
    assert cfg.analysis.max_files_count == 999
    assert cfg.ui.verbose is True


def test_cli_overrides_env_and_file_and_defaults(tmp_path: Path) -> None:
    custom_config = tmp_path / "codeguide.toml"
    custom_config.write_text(
        """
[llm]
model_name = "from-file"
""",
        encoding="utf-8",
    )

    env = {
        "CODEGUIDE_LLM__MODEL_NAME": "from-env",
    }

    cli_overrides = {
        "llm": {"model_name": "from-cli"},
        "paths": {"output_dir": "cli-out"},
    }

    cfg = load_config(config_path=custom_config, env=env, cli_overrides=cli_overrides)
    assert cfg.llm.model_name == "from-cli"
    assert cfg.paths.output_dir == "cli-out"


def test_deep_merge_preserves_nested_keys() -> None:
    base = {
        "a": {"k1": "v1", "k2": "v2"},
        "b": 100,
    }
    override = {
        "a": {"k2": "v2-updated", "k3": "v3"},
    }
    merged = deep_merge(base, override)
    assert merged == {
        "a": {"k1": "v1", "k2": "v2-updated", "k3": "v3"},
        "b": 100,
    }


def test_env_parser_types() -> None:
    env = {
        "CODEGUIDE_LLM__TEMPERATURE": "0.7",
        "CODEGUIDE_ANALYSIS__MAX_FILES_COUNT": "500",
        "CODEGUIDE_SECURITY__ALLOW_SYMLINKS": "false",
        "CODEGUIDE_ANALYSIS__SUPPORTED_EXTENSIONS": '["*.py", "*.rs"]',
        "OTHER_ENV": "ignored",
    }
    parsed = parse_env_overrides(env)
    assert parsed["llm"]["temperature"] == 0.7
    assert parsed["analysis"]["max_files_count"] == 500
    assert parsed["security"]["allow_symlinks"] is False
    assert parsed["analysis"]["supported_extensions"] == ["*.py", "*.rs"]
    assert "other_env" not in parsed


def test_validation_error_on_invalid_field_type(tmp_path: Path) -> None:
    invalid_config = tmp_path / "invalid.toml"
    invalid_config.write_text(
        """
[llm]
request_timeout_seconds = "not-a-number"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_config(config_path=invalid_config, env={})


def test_symlink_config_rejected_when_forbidden(tmp_path: Path) -> None:
    real_file = tmp_path / "real.toml"
    real_file.write_text("[ui]\nverbose = true\n", encoding="utf-8")
    symlink_file = tmp_path / "symlink.toml"

    try:
        symlink_file.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PermissionError):
        load_config(config_path=symlink_file, env={})


def test_oversized_config_file_rejected(tmp_path: Path) -> None:
    large_config = tmp_path / "huge.toml"
    # Write content exceeding 1048576 bytes
    large_config.write_text("#" * 1048577, encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds size limit"):
        load_config(config_path=large_config, env={})
