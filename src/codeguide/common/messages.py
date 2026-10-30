"""External message catalog provider."""

import importlib.resources
import tomllib
from pathlib import Path
from typing import Any


class MessageCatalog:
    """Manages externalized user-facing strings and message templates."""

    def __init__(self, catalog_dict: dict[str, Any]) -> None:
        self._catalog = catalog_dict

    @classmethod
    def load(cls, custom_path: Path | None = None) -> "MessageCatalog":
        # Load external messages to avoid hardcoded strings in code.
        if custom_path is not None and custom_path.is_file():
            with custom_path.open("rb") as f:
                data = tomllib.load(f)
        else:
            resource = importlib.resources.files("codeguide").joinpath("data", "messages.toml")
            with resource.open("rb") as f:
                data = tomllib.load(f)
        return cls(data)

    def get(self, key_path: str, **kwargs: Any) -> str:
        """Resolve a dot-notated key from catalog and format with keyword arguments."""
        keys = key_path.split(".")
        current: Any = self._catalog
        for k in keys:
            if not isinstance(current, dict) or k not in current:
                raise KeyError(f"Message key not found in catalog: {key_path}")
            current = current[k]

        if not isinstance(current, str):
            raise TypeError(f"Message key does not resolve to a string: {key_path}")

        return current.format(**kwargs) if kwargs else current


# Module-level default catalog instance
default_catalog = MessageCatalog.load()


def msg(key: str, **kwargs: Any) -> str:
    """Convenience accessor for default message catalog."""
    return default_catalog.get(key, **kwargs)
