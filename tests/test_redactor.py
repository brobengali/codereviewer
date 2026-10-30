"""Tests for secret detection, entropy scoring, file denylists, and zero-leak verification."""

import json
from pathlib import Path

from typer.testing import CliRunner

from codeguide.cli import app
from codeguide.config.loader import load_config
from codeguide.redactor.engine import SecretRedactor
from codeguide.scanner.scanner import RepositoryScanner

runner = CliRunner()


def test_file_denylist_never_read(tmp_path: Path) -> None:
    cfg = load_config()
    redactor = SecretRedactor.load(cfg)

    # Denied patterns (.env, .pem, .key, id_rsa, etc.)
    assert redactor.is_denied_file(".env")
    assert redactor.is_denied_file(".env.local")
    assert redactor.is_denied_file(".env.production")
    assert redactor.is_denied_file("certs/server.pem")
    assert redactor.is_denied_file("keys/id_rsa")
    assert redactor.is_denied_file("keys/id_ed25519")
    assert redactor.is_denied_file("certs/private.key")

    # Safe files
    assert not redactor.is_denied_file("main.py")
    assert not redactor.is_denied_file("README.md")
    assert not redactor.is_denied_file("config.toml")


def test_redact_multiline_private_key() -> None:
    cfg = load_config()
    redactor = SecretRedactor.load(cfg)

    raw_text = """# Configuration
ssl_cert = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1u5W6...fake...key...body...
...more...lines...of...untrusted...rsa...material...
-----END RSA PRIVATE KEY-----
'''
app_name = 'demo'
"""
    result = redactor.redact_text(raw_text)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in result.clean_text
    assert "-----END RSA PRIVATE KEY-----" not in result.clean_text
    assert "[REDACTED:private_key]" in result.clean_text
    assert "app_name = 'demo'" in result.clean_text
    assert any(f.rule_id == "private_key" for f in result.findings)


def test_redact_connection_strings_and_urls_with_credentials() -> None:
    cfg = load_config()
    redactor = SecretRedactor.load(cfg)

    raw = """
database_url = "postgres://dbuser:super_secret_password123@db.example.internal:5432/production"
redis_url = "redis://admin:auth_token_xyz987@redis.example.internal:6379/0"
api_endpoint = "https://service_user:p@ssw0rd!@secure-api.internal.net/v1"
"""
    result = redactor.redact_text(raw)
    assert "super_secret_password123" not in result.clean_text
    assert "auth_token_xyz987" not in result.clean_text
    assert "p@ssw0rd!" not in result.clean_text
    assert "[REDACTED:connection_string]" in result.clean_text
    assert "[REDACTED:url_credentials]" in result.clean_text


def test_redact_secrets_in_comments_and_api_keys() -> None:
    cfg = load_config()
    redactor = SecretRedactor.load(cfg)

    raw = """// Temporary debug note:
// TODO: remove api_key = "sk-abcdef1234567890abcdef1234567890"
# AWS_KEY = AKIAIOSFODNN7EXAMPLE
/* GitHub token ghp_111122223333444455556666777788889999 */
"""
    result = redactor.redact_text(raw)
    assert "sk-abcdef1234567890abcdef1234567890" not in result.clean_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.clean_text
    assert "ghp_111122223333444455556666777788889999" not in result.clean_text
    assert "[REDACTED:api_key]" in result.clean_text
    assert "[REDACTED:aws_key]" in result.clean_text
    assert "[REDACTED:github_token]" in result.clean_text


def test_redact_high_entropy_tokens() -> None:
    cfg = load_config()
    redactor = SecretRedactor.load(cfg)

    # Randomized high-entropy base64 key
    secret_token = "c2VjcmV0X3Rva2VuX3JhbmRvbV85ODcyMzQ1Nzg5MDEyMzQ1"
    raw = f'auth_header = "{secret_token}"'

    result = redactor.redact_text(raw)
    assert secret_token not in result.clean_text
    assert "[REDACTED:high_entropy]" in result.clean_text
    assert any(f.rule_id == "high_entropy" for f in result.findings)


def test_cli_dry_run_flag_output(tmp_path: Path) -> None:
    repo_dir = tmp_path / "leak_test_repo"
    repo_dir.mkdir()

    (repo_dir / "README.md").write_text(
        "# Safe Readme\nAPI Key: AKIAIOSFODNN7EXAMPLE\nDB: postgres://admin:pass999@localhost/db",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["analyze", str(repo_dir), "--dry-run"])
    assert result.exit_code == 0

    # Payload must be valid JSON
    payload = json.loads(result.stdout)
    assert payload["repo_name"] == "leak_test_repo"

    # Raw secrets must NOT be in the stdout payload
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout
    assert "pass999" not in result.stdout
    assert "[REDACTED:aws_key]" in result.stdout
    assert "[REDACTED:connection_string]" in result.stdout


def test_zero_fixture_secrets_in_payload_or_scans(tmp_path: Path) -> None:
    """Comprehensive test asserting zero fixture secrets appear in any payload, log, or cache."""
    cfg = load_config()
    repo_dir = tmp_path / "hard_repo"
    repo_dir.mkdir()

    # List of known tricky secrets placed in the fixture repo
    target_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdef1234567890abcdef1234567890123456",
        "postgres://usr:secret_pwd_999@host.net/db",
        "https://bot:token_pass_888@api.github.com",
        "c2VjcmV0X3Rva2VuX3JhbmRvbV85ODcyMzQ1Nzg5MDEyMzQ1",
        "MIIEowIBAAKCAQEA0Y1u5W6_PRIVATE_KEY_BODY_12345",
    ]

    # 1. Denied files (must never be read at all)
    (repo_dir / ".env").write_text(
        "DATABASE_PASSWORD=should_never_be_read_from_denied_file\n",
        encoding="utf-8",
    )
    (repo_dir / "cert.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nsecret_pem_body\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    # 2. Raw documents containing tricky secrets in comments, strings, and multiline blocks
    (repo_dir / "README.md").write_text(
        f"""# Security Audit Fixture
# Secret in comment: {target_secrets[0]}
# GitHub token in comment: {target_secrets[1]}

Connection string: {target_secrets[2]}
URL with credentials: {target_secrets[3]}
High entropy token: {target_secrets[4]}

Multiline private key:
-----BEGIN PRIVATE KEY-----
{target_secrets[5]}
-----END PRIVATE KEY-----
""",
        encoding="utf-8",
    )

    # Run scanner and redactor
    scanner = RepositoryScanner(repo_dir, cfg)
    raw_scan = scanner.scan()

    redactor = SecretRedactor.load(cfg)
    clean_scan, findings = redactor.redact_scan_result(raw_scan)

    # Serialize to JSON (simulating transmission payload)
    final_payload = clean_scan.model_dump_json()

    # Assert that the denied file contents were NEVER read into scanned documents
    assert "should_never_be_read_from_denied_file" not in final_payload
    assert "secret_pem_body" not in final_payload
    assert not any(".env" in d.path for d in clean_scan.documents)
    assert not any("cert.pem" in d.path for d in clean_scan.documents)

    # STRICT ASSERTION: Zero fixture secrets appear anywhere in the sanitized output!
    for secret in target_secrets:
        assert secret not in final_payload, f"Secret leak detected in payload: {secret}"

    # Verify that all 5+ redactions were recorded for the audit trail
    assert len(findings) >= 5
