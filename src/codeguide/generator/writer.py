"""Safe output file writer enforcing strict directory boundaries and filename whitelisting."""

import os
import re
from pathlib import Path

from codeguide.common.messages import msg


class UnsafeOutputError(ValueError):
    """Raised when an output path or filename violates security constraints."""


class SafeOutputWriter:
    """Enforces that output files are written strictly within the designated output directory."""

    FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

    def __init__(self, output_dir: Path, dir_mode: int = 0o700, file_mode: int = 0o600) -> None:
        self.output_dir = output_dir.resolve()
        self.dir_mode = dir_mode
        self.file_mode = file_mode

    def _validate_filename(self, filename: str) -> None:
        if not filename or "\0" in filename:
            raise UnsafeOutputError(msg("errors.unsafe_filename", filename=filename))

        if "/" in filename or "\\" in filename or ".." in filename:
            raise UnsafeOutputError(msg("errors.unsafe_filename", filename=filename))

        if filename in (".", "..") or not self.FILENAME_PATTERN.match(filename):
            raise UnsafeOutputError(msg("errors.unsafe_filename", filename=filename))

    def write_artifact(self, filename: str, content: str) -> Path:
        """Validate filename and write content securely inside the output directory."""
        self._validate_filename(filename)

        self.output_dir.mkdir(mode=self.dir_mode, parents=True, exist_ok=True)
        try:
            os.chmod(self.output_dir, self.dir_mode)
        except OSError:
            pass

        target_path = (self.output_dir / filename).resolve()

        if not target_path.is_relative_to(self.output_dir):
            raise UnsafeOutputError(
                msg("errors.output_traversal", path=str(target_path), root=str(self.output_dir))
            )

        target_path.write_text(content, encoding="utf-8")
        try:
            os.chmod(target_path, self.file_mode)
        except OSError:
            pass

        return target_path
