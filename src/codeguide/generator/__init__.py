"""Documentation generation package."""

from codeguide.generator.engine import DocumentationGenerator
from codeguide.generator.grounding import CitationGrounder
from codeguide.generator.html_escaper import (
    escape_html_text,
    safe_json_embed,
    sanitize_markdown_text,
)
from codeguide.generator.mermaid import (
    build_mermaid_architecture,
    sanitize_node_id,
    sanitize_node_label,
)
from codeguide.generator.models import OnboardingContext
from codeguide.generator.writer import SafeOutputWriter, UnsafeOutputError

__all__ = [
    "CitationGrounder",
    "DocumentationGenerator",
    "OnboardingContext",
    "SafeOutputWriter",
    "UnsafeOutputError",
    "build_mermaid_architecture",
    "escape_html_text",
    "safe_json_embed",
    "sanitize_markdown_text",
    "sanitize_node_id",
    "sanitize_node_label",
]
