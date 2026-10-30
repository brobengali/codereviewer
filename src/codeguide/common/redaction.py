"""Secret detection, masking, and redaction mechanisms."""

import math
import re
from typing import Any


def mask_sensitive_dict(
    data: dict[str, Any],
    sensitive_keys: list[str],
    mask_value: str = "********",
) -> dict[str, Any]:
    """Recursively mask sensitive values in a dictionary."""
    normalized_keys = {k.lower() for k in sensitive_keys}
    masked: dict[str, Any] = {}

    for key, value in data.items():
        key_lower = str(key).lower()
        suffixes = ("_key", "_secret", "_token", "_password")
        is_sensitive = key_lower in normalized_keys or any(
            key_lower.endswith(suffix) for suffix in suffixes
        )

        if is_sensitive and isinstance(value, str) and value:
            masked[key] = mask_value
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_dict(value, sensitive_keys, mask_value=mask_value)
        else:
            masked[key] = value

    return masked


def redact_text(text: str, patterns: list[str], marker: str = "[REDACTED]") -> str:
    """Replace secret regex pattern matches in text with a redaction marker."""
    if not text:
        return text

    redacted = text
    for pat in patterns:
        try:
            compiled = re.compile(pat)
            redacted = compiled.sub(marker, redacted)
        except re.error:
            continue
    return redacted


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy to identify high-randomness tokens."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    frequencies = {char: data.count(char) for char in set(data)}

    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy
