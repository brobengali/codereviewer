"""Secure, validated generation cache with strict filesystem permissions."""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from codeguide.common.messages import msg
from codeguide.config.models import LLMConfig

logger = logging.getLogger("codeguide.llm.cache")


class LLMCache:
    """Stores and retrieves validated generation artifacts backed by SHA-256 keys."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.cache_dir = Path(config.cache_dir)
        if config.cache_enabled:
            self._init_cache_dir()

    def _init_cache_dir(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.cache_dir, 0o700)
        except OSError:
            pass
        self._verify_dir_permissions()

    def _verify_dir_permissions(self) -> None:
        if os.name == "posix":
            st = self.cache_dir.stat()
            if (st.st_mode & 0o077) != 0:
                try:
                    os.chmod(self.cache_dir, 0o700)
                except OSError as exc:
                    raise PermissionError(
                        msg(
                            "errors.cache_permission_error",
                            path=str(self.cache_dir),
                            expected="0700",
                            actual=oct(st.st_mode),
                        )
                    ) from exc

    def compute_key(
        self,
        redacted_content: str,
        template_version: str,
        model_name: str,
        schema_version: str,
    ) -> str:
        h = hashlib.sha256()
        h.update(redacted_content.encode("utf-8"))
        h.update(b"|")
        h.update(template_version.encode("utf-8"))
        h.update(b"|")
        h.update(model_name.encode("utf-8"))
        h.update(b"|")
        h.update(schema_version.encode("utf-8"))
        return h.hexdigest()

    def get(self, cache_key: str) -> dict[str, Any] | None:
        if not self.config.cache_enabled:
            return None

        cache_file = self.cache_dir / f"{cache_key}.json"
        if not cache_file.is_file():
            return None

        if os.name == "posix":
            st = cache_file.stat()
            if (st.st_mode & 0o077) != 0:
                try:
                    os.chmod(cache_file, 0o600)
                except OSError:
                    return None

        try:
            with cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("result")
        except Exception as exc:
            logger.debug("Failed reading cache file %s: %s", cache_file, exc)
            return None

    def set(
        self,
        cache_key: str,
        redacted_content: str,
        validated_result: dict[str, Any],
    ) -> None:
        if not self.config.cache_enabled:
            return

        self._init_cache_dir()
        cache_file = self.cache_dir / f"{cache_key}.json"
        payload = {
            "key": cache_key,
            "content": redacted_content,
            "result": validated_result,
        }

        # Write with 0600 mode
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(cache_file, flags, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        try:
            os.chmod(cache_file, 0o600)
        except OSError:
            pass
