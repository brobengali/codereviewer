"""Secure repository loader with SSRF protection, traversal prevention, and sandboxed cloning."""

import ipaddress
import os
import shutil
import signal
import socket
import subprocess  # nosec B404
import tempfile
import time
import urllib.parse
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codeguide.common.messages import msg
from codeguide.config.models import AppConfig


@dataclass(frozen=True)
class ScannedFile:
    """Represents a validated, within-boundary repository file."""

    relative_path: str
    absolute_path: Path
    size_bytes: int


def _is_ip_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    blocked_networks: list[str],
) -> bool:
    # Check default internal designations before iterating configured CIDRs.
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    for cidr in blocked_networks:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def validate_git_url(url: str, config: AppConfig) -> urllib.parse.ParseResult:
    """Validate remote Git URL against scheme, host allowlists, and SSRF restrictions."""
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in config.repo.allowed_schemes:
        raise ValueError(
            msg("errors.invalid_scheme", scheme=scheme, allowed=config.repo.allowed_schemes)
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(msg("errors.host_not_allowed", host=""))

    normalized_host = hostname.lower()
    allowed_hosts = [h.lower() for h in config.repo.allowed_hosts]

    if not config.repo.allow_all_hosts and normalized_host not in allowed_hosts:
        raise ValueError(msg("errors.host_not_allowed", host=normalized_host))

    # Resolve all associated IP addresses to detect DNS rebinding or direct IP references.
    try:
        addr_info = socket.getaddrinfo(normalized_host, None)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failure for host '{normalized_host}': {exc}") from exc

    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if config.security.block_private_ips and _is_ip_blocked(
            ip_obj, config.security.blocked_ip_networks
        ):
            raise PermissionError(msg("errors.ssrf_blocked_ip", host=normalized_host, ip=ip_str))

    return parsed


def clone_git_repo(url: str, destination: Path, config: AppConfig) -> Path:
    """Clone remote Git repository with security hardening options."""
    git_bin = shutil.which(config.repo.git_binary)
    if not git_bin:
        raise FileNotFoundError(msg("errors.git_not_found", binary=config.repo.git_binary))

    # Disable hooks, credential helpers, and submodules to isolate untrusted remote execution.
    cmd = [
        git_bin,
        "-c",
        "core.hooksPath=",
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        str(config.repo.clone_depth),
        "--no-recurse-submodules",
        "--",
        url,
        str(destination),
    ]

    # Strip ambient GIT_* environment variables to prevent environment injection.
    safe_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

    try:
        # Command array and URL are validated; ambient env stripped to isolate execution.
        subprocess.run(  # nosec B603 # noqa: S603
            cmd,
            env=safe_env,
            timeout=config.repo.clone_timeout_seconds,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            msg("errors.git_clone_failed", code=exc.returncode, detail=exc.stderr.strip())
        ) from exc
    except subprocess.TimeoutExpired as exc:
        timeout_err = msg("errors.scan_timeout", seconds=config.repo.clone_timeout_seconds)
        raise TimeoutError(timeout_err) from exc

    return destination


def safe_extract_zip(zip_path: Path, destination: Path, config: AppConfig) -> Path:
    """Safely extract zip archive enforcing traversal and decompression explosion bounds."""
    resolved_dest = destination.resolve()
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()
            total_bytes = 0
            file_count = 0

            for member in infolist:
                # 1. Zip slip / path traversal protection
                member_path = Path(member.filename)
                target_path = (resolved_dest / member_path).resolve()
                if not target_path.is_relative_to(resolved_dest):
                    raise PermissionError(msg("errors.zip_slip", path=member.filename))

                if member.is_dir():
                    continue

                file_count += 1
                if file_count > config.analysis.max_files_count:
                    raise ValueError(
                        msg(
                            "errors.zip_bomb_file_count",
                            count=file_count,
                            limit=config.analysis.max_files_count,
                        )
                    )

                # 2. Member uncompressed size check
                if member.file_size > config.analysis.max_file_size_bytes:
                    raise ValueError(
                        msg(
                            "errors.zip_bomb_size",
                            path=member.filename,
                            size=member.file_size,
                            limit=config.analysis.max_file_size_bytes,
                        )
                    )

                # 3. Compression ratio check (zip bomb)
                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    if ratio > config.security.max_compression_ratio:
                        raise ValueError(
                            msg(
                                "errors.zip_bomb_ratio",
                                path=member.filename,
                                limit=config.security.max_compression_ratio,
                            )
                        )

                # 4. Cumulative uncompressed size check
                total_bytes += member.file_size
                if total_bytes > config.analysis.max_repo_size_bytes:
                    raise ValueError(
                        msg(
                            "errors.zip_bomb_total_size",
                            size=total_bytes,
                            limit=config.analysis.max_repo_size_bytes,
                        )
                    )

            # Safe extraction after all checks pass
            for member in infolist:
                member_path = Path(member.filename)
                target_path = (resolved_dest / member_path).resolve()
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                else:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, target_path.open("wb") as dest_file:
                        shutil.copyfileobj(source, dest_file)
    except zipfile.BadZipFile as exc:
        raise ValueError(msg("errors.zip_corrupt", detail=str(exc))) from exc

    return destination


class SecureRepoContext:
    """Context manager providing isolated, verified local repository access."""

    def __init__(self, target: str | Path, config: AppConfig) -> None:
        self.target = str(target)
        self.config = config
        self.repo_path: Path | None = None
        self.is_temporary = False
        self._previous_sigint: Any = None

    def __enter__(self) -> Path:
        parsed = urllib.parse.urlparse(self.target)
        # Windows drive letters (e.g. C:) must not be treated as URL schemes.
        drive, _ = os.path.splitdrive(self.target)
        is_windows_drive = bool(drive) or (len(parsed.scheme) == 1 and parsed.scheme.isalpha())
        is_remote = not is_windows_drive and (
            bool(parsed.scheme) or "://" in self.target or self.target.startswith("git@")
        )

        # Remote URL validation and shallow cloning into isolated workspace.
        if is_remote:
            validate_git_url(self.target, self.config)
            temp_dir = Path(tempfile.mkdtemp(prefix=self.config.repo.temp_dir_prefix))
            try:
                os.chmod(temp_dir, self.config.repo.dir_mode)
            except OSError:
                pass  # Windows may not support full POSIX permission bits
            self.repo_path = temp_dir
            self.is_temporary = True
            self._register_interrupt_cleanup()
            try:
                clone_git_repo(self.target, temp_dir, self.config)
            except BaseException:
                # Clean up isolated workspace immediately if interrupted or failed during entry.
                if self.repo_path and self.repo_path.exists():
                    shutil.rmtree(self.repo_path, ignore_errors=True)
                self._restore_interrupt_handler()
                raise
        else:
            local_path = Path(self.target).resolve()
            if not local_path.exists():
                raise FileNotFoundError(msg("cli.target_not_dir", path=local_path))
            if local_path.is_file() and (
                local_path.suffix.lower() == ".zip" or zipfile.is_zipfile(local_path)
            ):
                temp_dir = Path(tempfile.mkdtemp(prefix=self.config.repo.temp_dir_prefix))
                try:
                    os.chmod(temp_dir, self.config.repo.dir_mode)
                except OSError:
                    pass
                self.repo_path = temp_dir
                self.is_temporary = True
                self._register_interrupt_cleanup()
                try:
                    safe_extract_zip(local_path, temp_dir, self.config)
                except BaseException:
                    if self.repo_path and self.repo_path.exists():
                        shutil.rmtree(self.repo_path, ignore_errors=True)
                    self._restore_interrupt_handler()
                    raise
            elif not local_path.is_dir():
                raise FileNotFoundError(msg("cli.target_not_dir", path=local_path))
            else:
                self.repo_path = local_path

        return self.repo_path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._restore_interrupt_handler()
        if self.is_temporary and self.repo_path and self.repo_path.exists():
            shutil.rmtree(self.repo_path, ignore_errors=True)

    def _register_interrupt_cleanup(self) -> None:
        # Guarantee removal of temporary workspace if user sends SIGINT.
        def _handle_interrupt(signum: int, frame: Any) -> None:
            if self.is_temporary and self.repo_path and self.repo_path.exists():
                shutil.rmtree(self.repo_path, ignore_errors=True)
            self._restore_interrupt_handler()
            raise KeyboardInterrupt

        try:
            self._previous_sigint = signal.signal(signal.SIGINT, _handle_interrupt)
        except (ValueError, AttributeError):
            pass

    def _restore_interrupt_handler(self) -> None:
        if self._previous_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._previous_sigint)
            except (ValueError, AttributeError):
                pass
            self._previous_sigint = None


def scan_repository(repo_root: Path, config: AppConfig) -> list[ScannedFile]:
    """Scan and validate repository files against traversal, symlink escapes, and size limits."""
    resolved_root = repo_root.resolve()
    start_time = time.monotonic()

    scanned_files: list[ScannedFile] = []
    total_repo_bytes = 0

    for current_root, dirs, files in os.walk(resolved_root):
        current_path = Path(current_root)

        # Prune ignored directory patterns in-place to avoid unnecessary traversal.
        dirs[:] = [
            d
            for d in dirs
            if not any(Path(d).match(pat) for pat in config.analysis.ignore_patterns)
        ]

        for file_name in files:
            if any(Path(file_name).match(pat) for pat in config.analysis.ignore_patterns):
                continue

            # Check scan time ceiling to prevent algorithmic DoS.
            if time.monotonic() - start_time > config.repo.scan_timeout_seconds:
                raise TimeoutError(
                    msg("errors.scan_timeout", seconds=config.repo.scan_timeout_seconds)
                )

            file_path = current_path / file_name

            # Guard against symlinks pointing outside the repository boundary.
            if file_path.is_symlink():
                if not config.security.allow_symlinks:
                    continue
                resolved_target = file_path.resolve()
                if not resolved_target.is_relative_to(resolved_root):
                    raise PermissionError(
                        msg("errors.symlink_escape", path=file_path, target=resolved_target)
                    )

            resolved_file = file_path.resolve()
            if not resolved_file.is_relative_to(resolved_root):
                raise PermissionError(
                    msg("errors.path_traversal", path=file_path, root=resolved_root)
                )

            try:
                file_size = file_path.stat().st_size
            except OSError:
                continue

            if file_size > config.analysis.max_file_size_bytes:
                raise ValueError(
                    msg(
                        "errors.file_size_exceeded",
                        path=file_name,
                        size=file_size,
                        limit=config.analysis.max_file_size_bytes,
                    )
                )

            total_repo_bytes += file_size
            if total_repo_bytes > config.analysis.max_repo_size_bytes:
                raise ValueError(
                    msg(
                        "errors.repo_size_exceeded",
                        size=total_repo_bytes,
                        limit=config.analysis.max_repo_size_bytes,
                    )
                )

            rel_path = file_path.relative_to(resolved_root).as_posix()
            scanned_files.append(
                ScannedFile(
                    relative_path=rel_path,
                    absolute_path=resolved_file,
                    size_bytes=file_size,
                )
            )

            if len(scanned_files) > config.analysis.max_files_count:
                raise ValueError(
                    msg(
                        "errors.file_count_exceeded",
                        count=len(scanned_files),
                        limit=config.analysis.max_files_count,
                    )
                )

    return scanned_files
