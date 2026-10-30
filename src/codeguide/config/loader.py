"""Configuration loader implementing precedence hierarchy."""

import importlib.resources
import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codeguide.common.messages import msg
from codeguide.config.models import AppConfig


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override dictionary into base dictionary."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _parse_scalar(val: str) -> Any:
    # Scalar parsing to convert string environment variables into typed values.
    normalized = val.strip()
    lower = normalized.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False

    if (normalized.startswith("[") and normalized.endswith("]")) or (
        normalized.startswith("{") and normalized.endswith("}")
    ):
        try:
            return json.loads(normalized)
        except json.JSONDecodeError:
            pass

    try:
        return int(normalized)
    except ValueError:
        pass

    try:
        return float(normalized)
    except ValueError:
        pass

    return val


def parse_env_overrides(env: Mapping[str, str], prefix: str = "CODEGUIDE_") -> dict[str, Any]:
    """Parse nested config overrides from environment variables matching prefix."""
    overrides: dict[str, Any] = {}
    for raw_key, raw_val in env.items():
        if not raw_key.startswith(prefix):
            continue
        body = raw_key[len(prefix) :]
        # Reserved top-level flag pointing to config file location
        if body == "CONFIG":
            continue

        parts = [p.lower() for p in body.split("__") if p]
        if not parts:
            continue

        current = overrides
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = _parse_scalar(raw_val)

    return overrides


def safe_read_toml(
    path: Path,
    max_bytes: int | None = None,
    allow_symlinks: bool = True,
) -> dict[str, Any]:
    """Safely read and parse a TOML file with size and symlink validation."""
    if not path.is_file():
        raise FileNotFoundError(msg("errors.file_not_found", path=path))

    # Untrusted repo defense: reject symlinks if configured to prevent directory escape.
    if not allow_symlinks and path.is_symlink():
        raise PermissionError(msg("errors.symlinks_disallowed", path=path))

    # Guard against memory exhaustion DoS from maliciously large files.
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError(msg("errors.file_exceeds_size", limit=max_bytes, path=path))

    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(
    config_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    defaults_path: Path | None = None,
) -> AppConfig:
    """Load configuration enforcing: CLI flags > env vars > codeguide.toml > defaults.toml."""
    env_vars = os.environ if env is None else env

    # 1. Baseline: versioned defaults file packaged with the tool
    if defaults_path is None:
        resource = importlib.resources.files("codeguide").joinpath("data", "defaults.toml")
        with resource.open("rb") as f:
            merged: dict[str, Any] = tomllib.load(f)
    else:
        merged = safe_read_toml(defaults_path)

    default_meta = merged.get("meta", {})
    default_security = merged.get("security", {})
    default_analysis = merged.get("analysis", {})

    config_filename = default_meta.get("config_filename", "codeguide.toml")
    max_file_bytes = default_analysis.get("max_file_size_bytes")
    allow_symlinks = default_security.get("allow_symlinks", False)

    # 2. File config: path from CLI, env, or repo root
    resolved_config_path: Path | None = None
    if config_path is not None:
        resolved_config_path = config_path
    elif "CODEGUIDE_CONFIG" in env_vars:
        resolved_config_path = Path(env_vars["CODEGUIDE_CONFIG"])
    else:
        candidate = Path.cwd() / config_filename
        if candidate.is_file():
            resolved_config_path = candidate

    if resolved_config_path is not None and resolved_config_path.is_file():
        file_config = safe_read_toml(
            resolved_config_path,
            max_bytes=max_file_bytes,
            allow_symlinks=allow_symlinks,
        )
        merged = deep_merge(merged, file_config)

    # 3. Environment variable overrides
    env_overrides = parse_env_overrides(env_vars)
    if env_overrides:
        merged = deep_merge(merged, env_overrides)

    # 4. Explicit CLI flag overrides
    if cli_overrides:
        merged = deep_merge(merged, cli_overrides)

    return AppConfig.model_validate(merged)
