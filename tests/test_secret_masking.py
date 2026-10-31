"""Tests for secret masking in configuration outputs and structured logging."""

import json
import logging
from pathlib import Path

from typer.testing import CliRunner

from codeguide.cli import app
from codeguide.common.logging import StructuredRedactingFormatter
from codeguide.common.redaction import calculate_entropy, mask_sensitive_dict, redact_text

runner = CliRunner()


def test_mask_sensitive_dict() -> None:
    data = {
        "provider": "gemini",
        "api_key": "super-secret-key-12345",
        "nested": {
            "auth_token": "bearer-token-abcde",
            "model_name": "gemini-3.5-flash",
            "user_password": "my_password",
        },
        "public_setting": "visible",
    }
    sensitive_keys = ["api_key", "auth_token", "password"]
    masked = mask_sensitive_dict(data, sensitive_keys, mask_value="********")

    assert masked["provider"] == "gemini"
    assert masked["api_key"] == "********"
    assert masked["nested"]["auth_token"] == "********"
    assert masked["nested"]["model_name"] == "gemini-3.5-flash"
    assert masked["nested"]["user_password"] == "********"
    assert masked["public_setting"] == "visible"


def test_cli_config_show_masks_secrets(tmp_path: Path) -> None:
    config_file = tmp_path / "codeguide.toml"
    config_file.write_text(
        """
[llm]
api_key = "real-production-api-key"
model_name = "test-model"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["config", "show", "--config", str(config_file)])
    assert result.exit_code == 0

    # Ensure real key is nowhere in stdout
    assert "real-production-api-key" not in result.stdout
    assert '"api_key": "********"' in result.stdout
    assert '"model_name": "test-model"' in result.stdout


def test_redact_text_with_patterns() -> None:
    patterns = [
        r"(?i)api_key\s*=\s*['\"][^'\"]+['\"]",
        r"sk-[a-zA-Z0-9]{10,}",
    ]
    raw = "Connecting with api_key='secret12345678' and backup key sk-1234567890abcdef"
    redacted = redact_text(raw, patterns, marker="[REDACTED]")

    assert "secret12345678" not in redacted
    assert "sk-1234567890abcdef" not in redacted
    assert "[REDACTED]" in redacted


def test_structured_logging_automatic_redaction() -> None:
    patterns = [r"SECRET_[A-Z0-9]+"]
    formatter = StructuredRedactingFormatter(patterns=patterns, marker="[REDACTED]")

    record = logging.LogRecord(
        name="codeguide.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Leaked token: SECRET_ABC123456 in log message",
        args=(),
        exc_info=None,
    )
    # Add structured attribute containing a secret
    record.custom_secret = "SECRET_XYZ987654"  # type: ignore[attr-defined]

    output = formatter.format(record)
    parsed = json.loads(output)

    assert "SECRET_ABC123456" not in parsed["message"]
    assert "[REDACTED]" in parsed["message"]
    assert parsed["custom_secret"] == "[REDACTED]"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "codeguide.test"


def test_calculate_entropy() -> None:
    # Low entropy (repetitive)
    low_entropy = calculate_entropy("aaaaaaaaaaaa")
    # High entropy (randomized key)
    high_entropy = calculate_entropy("x8K9#mQ2$vL1!pZ7")
    assert high_entropy > low_entropy
    assert low_entropy == 0.0
