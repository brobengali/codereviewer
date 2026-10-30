"""Security tests verifying SSRF protection, traversal defense, symlink containment, and cleanup."""

import socket
from pathlib import Path

import pytest

from codeguide.config.loader import load_config
from codeguide.repo.loader import (
    SecureRepoContext,
    scan_repository,
    validate_git_url,
)


def test_ssrf_disallowed_schemes() -> None:
    cfg = load_config()
    for bad_url in (
        "file:///etc/passwd",
        "ftp://example.com/repo.git",
        "git://example.com/repo.git",
    ):
        with pytest.raises(ValueError, match="scheme .* not permitted"):
            validate_git_url(bad_url, cfg)


def test_ssrf_disallowed_hosts() -> None:
    cfg = load_config()
    with pytest.raises(ValueError, match="not in the allowed host list"):
        validate_git_url("https://malicious-domain.org/exploit.git", cfg)


def test_ssrf_blocked_loopback_and_private_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config()
    # Direct IP addresses
    private_ips = (
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.100",
        "169.254.169.254",  # AWS/Cloud metadata
        "::1",
    )

    for ip in private_ips:
        # Bind loop variable explicitly to default argument
        def fake_getaddrinfo(host: str, port: int | None, target_ip: str = ip) -> list[tuple]:
            family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
            return [(family, socket.SOCK_STREAM, 6, "", (target_ip, 443))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(PermissionError, match="blocked IP address"):
            validate_git_url("https://github.com/org/repo.git", cfg)


def test_symlink_escape_detected(tmp_path: Path) -> None:
    cfg = load_config(cli_overrides={"security": {"allow_symlinks": True}})

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "safe.py").write_text("print('safe')", encoding="utf-8")

    outside_file = tmp_path / "secret.env"
    outside_file.write_text("SUPER_SECRET=1", encoding="utf-8")

    symlink_file = repo_dir / "escape_link.py"
    try:
        symlink_file.symlink_to(outside_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted on this platform/privilege level")

    with pytest.raises(PermissionError, match="points outside repository boundary"):
        scan_repository(repo_dir, cfg)


def test_symlinks_ignored_when_disabled(tmp_path: Path) -> None:
    cfg = load_config(cli_overrides={"security": {"allow_symlinks": False}})

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "safe.py").write_text("print('safe')", encoding="utf-8")

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")

    symlink_file = repo_dir / "link.txt"
    try:
        symlink_file.symlink_to(outside_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted on this platform/privilege level")

    files = scan_repository(repo_dir, cfg)
    assert len(files) == 1
    assert files[0].relative_path == "safe.py"


def test_oversized_file_limit_enforced(tmp_path: Path) -> None:
    cfg = load_config(cli_overrides={"analysis": {"max_file_size_bytes": 100}})
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Create file of 150 bytes (exceeds 100 limit)
    (repo_dir / "large.py").write_text("A" * 150, encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds limit"):
        scan_repository(repo_dir, cfg)


def test_oversized_repo_limit_enforced(tmp_path: Path) -> None:
    overrides = {"analysis": {"max_repo_size_bytes": 200, "max_file_size_bytes": 150}}
    cfg = load_config(cli_overrides=overrides)
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Two 120-byte files total 240 bytes (exceeds 200 repo limit)
    (repo_dir / "f1.py").write_text("B" * 120, encoding="utf-8")
    (repo_dir / "f2.py").write_text("C" * 120, encoding="utf-8")

    with pytest.raises(ValueError, match="Repository total size .* exceeds limit"):
        scan_repository(repo_dir, cfg)


def test_file_count_limit_enforced(tmp_path: Path) -> None:
    cfg = load_config(cli_overrides={"analysis": {"max_files_count": 2}})
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    for i in range(3):
        (repo_dir / f"f{i}.py").write_text("ok", encoding="utf-8")

    with pytest.raises(ValueError, match="Repository file count .* exceeds limit"):
        scan_repository(repo_dir, cfg)


def test_scan_timeout_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config(cli_overrides={"repo": {"scan_timeout_seconds": 0.001}})
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "file1.py").write_text("content", encoding="utf-8")

    import time

    real_monotonic = time.monotonic
    calls = 0

    def fake_monotonic() -> float:
        nonlocal calls
        calls += 1
        # Advance time by 10 seconds on second check
        return real_monotonic() + (10.0 if calls > 1 else 0.0)

    monkeypatch.setattr(time, "monotonic", fake_monotonic)

    with pytest.raises(TimeoutError, match="Repository scan timed out"):
        scan_repository(repo_dir, cfg)


def test_cleanup_on_interrupt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config()
    created_temp_dirs: list[Path] = []

    # Mock validate_git_url and clone_git_repo to simulate clone process
    monkeypatch.setattr("codeguide.repo.loader.validate_git_url", lambda url, c: None)

    def fake_clone(url: str, dest: Path, c: any) -> Path:
        created_temp_dirs.append(dest)
        # Simulate interruption during clone
        raise KeyboardInterrupt

    monkeypatch.setattr("codeguide.repo.loader.clone_git_repo", fake_clone)

    with pytest.raises(KeyboardInterrupt):
        with SecureRepoContext("https://github.com/valid/repo.git", cfg):
            pass

    assert len(created_temp_dirs) == 1
    # Verify directory was completely purged
    assert not created_temp_dirs[0].exists()
