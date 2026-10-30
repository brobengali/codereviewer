"""Tests for external message catalog."""

from pathlib import Path

import pytest

from codeguide.common.messages import MessageCatalog, msg


def test_default_message_catalog_retrieval() -> None:
    app_help = msg("cli.app_help")
    assert isinstance(app_help, str)
    assert len(app_help) > 0


def test_parameterized_message_formatting() -> None:
    text = msg("cli.version_output", version="1.2.3", schema_version="2.0.0")
    assert "CodeGuide: 1.2.3" in text
    assert "Defaults schema version: 2.0.0" in text


def test_missing_message_key_raises_key_error() -> None:
    with pytest.raises(KeyError, match="Message key not found"):
        msg("nonexistent.nested.key")


def test_custom_catalog_loading(tmp_path: Path) -> None:
    custom_msg_file = tmp_path / "custom_messages.toml"
    custom_msg_file.write_text(
        """
[alerts]
greeting = "Hello, {name}!"
""",
        encoding="utf-8",
    )

    catalog = MessageCatalog.load(custom_path=custom_msg_file)
    result = catalog.get("alerts.greeting", name="Alice")
    assert result == "Hello, Alice!"
