"""Secure API key encapsulation, keychain retrieval, and log redaction."""

import logging
import os

import keyring

from codeguide.config.models import LLMConfig

logger = logging.getLogger("codeguide.llm.key")


class SecretKey:
    """Wrapper that prevents sensitive credential strings from leaking."""

    def __init__(self, raw_value: str) -> None:
        self._raw_value = raw_value

    def get_secret_value(self) -> str:
        return self._raw_value

    def __repr__(self) -> str:
        return "********"

    def __str__(self) -> str:
        return "********"

    def __format__(self, format_spec: str) -> str:
        return "********"

    def __bool__(self) -> bool:
        return bool(self._raw_value)


class KeyMaskingFilter(logging.Filter):
    """Logging filter ensuring API keys never appear in log records."""

    def __init__(self, key_to_mask: str) -> None:
        super().__init__()
        self._key = key_to_mask

    def filter(self, record: logging.LogRecord) -> bool:
        if self._key and len(self._key) >= 4:
            if isinstance(record.msg, str):
                record.msg = record.msg.replace(self._key, "********")
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: (v.replace(self._key, "********") if isinstance(v, str) else v)
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        (a.replace(self._key, "********") if isinstance(a, str) else a)
                        for a in record.args
                    )
        return True


def resolve_api_key(config: LLMConfig) -> SecretKey | None:
    # 1. Environment variable
    env_name = config.api_key_env_var
    env_val = os.environ.get(env_name)
    if env_val and env_val.strip():
        return SecretKey(env_val.strip())

    # 2. Operating system keychain
    try:
        kr_val = keyring.get_password(config.keyring_service_name, config.keyring_username)
        if kr_val and kr_val.strip():
            return SecretKey(kr_val.strip())
    except Exception as exc:
        logger.debug("Keyring lookup failed: %s", exc)

    return None
