"""Gitignore and exclusion rules matching."""

import fnmatch
from pathlib import Path

from codeguide.config.models import AppConfig


class GitIgnoreFilter:
    """Evaluates whether paths should be excluded based on gitignore and configured filters."""

    def __init__(self, repo_root: Path, config: AppConfig) -> None:
        self.repo_root = repo_root.resolve()
        self.config = config
        self._gitignore_patterns = self._load_gitignore()

    def _load_gitignore(self) -> list[str]:
        # Read untrusted .gitignore lines safely; strip comments and whitespace.
        patterns: list[str] = []
        gitignore_path = self.repo_root / ".gitignore"
        if gitignore_path.is_file():
            try:
                raw_text = gitignore_path.read_text(encoding="utf-8", errors="ignore")
                for line in raw_text.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        patterns.append(stripped)
            except OSError:
                pass
        return patterns

    def is_ignored(self, relative_path: str, is_dir: bool = False) -> bool:
        """Return True if path matches gitignore, lockfiles, build output, or ignore patterns."""
        normalized = relative_path.replace("\\", "/").strip("/")
        parts = normalized.split("/")

        # 0. Strictly refuse to touch denied sensitive files (.env, .pem, .key, etc.)
        for denypat in self.config.security.denied_file_patterns:
            if fnmatch.fnmatch(parts[-1], denypat) or fnmatch.fnmatch(normalized, denypat):
                return True

        # 1. Skip configured build directories and ignore patterns
        for build_dir in self.config.analysis.build_directories:
            if build_dir in parts:
                return True

        for pat in self.config.analysis.ignore_patterns:
            if fnmatch.fnmatch(normalized, pat) or any(fnmatch.fnmatch(p, pat) for p in parts):
                return True

        # 2. Check lockfiles (only for files)
        if not is_dir:
            for lock_pat in self.config.analysis.lockfile_patterns:
                if fnmatch.fnmatch(parts[-1], lock_pat):
                    return True

            # Check binary extensions
            ext = "." + parts[-1].split(".")[-1].lower() if "." in parts[-1] else ""
            if ext and ext in self.config.analysis.binary_extensions:
                return True

        # 3. Match against repository .gitignore rules
        for pat in self._gitignore_patterns:
            clean_pat = pat.rstrip("/")
            if fnmatch.fnmatch(normalized, clean_pat) or fnmatch.fnmatch(parts[-1], clean_pat):
                return True
            # Match subpaths (e.g. dir/*)
            if fnmatch.fnmatch(normalized, f"{clean_pat}/*"):
                return True

        return False

    def is_binary_file(self, full_path: Path) -> bool:
        """Inspect file header to detect unreadable binary formats."""
        try:
            with full_path.open("rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except OSError:
            return True
