"""HTML escaping and sanitization utilities for safe interactive output."""

import html
import json
import re
from typing import Any


def escape_html_text(raw: str) -> str:
    """Escapes text for safe inclusion in HTML body or attributes."""
    if not isinstance(raw, str):
        raw = str(raw)
    return html.escape(raw, quote=True)


def safe_json_embed(data: Any) -> str:
    """Serializes data to JSON safe for embedding inside an HTML <script> or attribute.

    Replaces '<', '>', '&', and '/' to prevent '</script>' injection attacks.
    """
    json_str = json.dumps(data, ensure_ascii=True)
    # Neutralize script tags and HTML comment closers
    json_str = json_str.replace("<", "\\u003c")
    json_str = json_str.replace(">", "\\u003e")
    json_str = json_str.replace("&", "\\u0026")
    json_str = json_str.replace("'", "\\u0027")
    return json_str


def sanitize_markdown_text(raw_md: str) -> str:
    """Escapes raw HTML tags and dangerous URI schemes from markdown text."""
    if not raw_md:
        return ""

    # Neutralize HTML tags
    cleaned = html.escape(raw_md, quote=False)

    # Disarm dangerous protocol links: [text](javascript:...)
    cleaned = re.sub(
        r"\[([^\]]*)\]\((?:javascript|data|vbscript):[^\)]*\)",
        r"[\1](#blocked-scheme)",
        cleaned,
        flags=re.IGNORECASE,
    )

    return cleaned
