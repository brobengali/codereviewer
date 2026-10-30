"""Mermaid diagram generation with strict sanitization against syntax injection."""

import hashlib
import re


def sanitize_node_id(raw_name: str) -> str:
    """Generate a deterministic, alphanumeric identifier safe for Mermaid syntax."""
    # Prefix with letter to guarantee valid Mermaid identifier
    digest = hashlib.sha256(raw_name.encode("utf-8")).hexdigest()[:8]
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", raw_name.strip())
    truncated = cleaned[:16].strip("_")
    return f"node_{truncated}_{digest}" if truncated else f"node_{digest}"


def sanitize_node_label(raw_label: str) -> str:
    """Escape and sanitize text inside Mermaid node labels ["..."]."""
    if not raw_label:
        return "unnamed"

    # Replace newlines with spaces and neutralize injection characters
    sanitized = raw_label.replace("\r", " ").replace("\n", " ")
    sanitized = sanitized.replace('"', "'")
    sanitized = sanitized.replace("[", "&#91;").replace("]", "&#93;")
    sanitized = sanitized.replace("(", "&#40;").replace(")", "&#41;")
    sanitized = sanitized.replace("{", "&#123;").replace("}", "&#125;")
    sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
    sanitized = sanitized.replace(";", "&#59;")
    sanitized = sanitized.replace("`", "")

    # Neutralize dangerous Mermaid directives
    for directive in ("click ", "style ", "classDef ", "class ", "callback ", "subgraph ", "end "):
        sanitized = re.sub(
            re.escape(directive), f"_{directive.strip()}_ ", sanitized, flags=re.IGNORECASE
        )

    return sanitized.strip()[:80]


def build_mermaid_architecture(
    architecture_name: str,
    modules: list[str],
    dependencies: list[tuple[str, str]],
    max_nodes: int = 25,
    max_edges: int = 50,
) -> str:
    """Build a sanitized Mermaid flowchart representing architecture and module relationships."""
    safe_arch_name = sanitize_node_label(architecture_name or "Architecture")
    lines = ["flowchart TD", f'  subgraph Arch ["Pattern: {safe_arch_name}"]']

    selected_modules = modules[:max_nodes]
    node_id_map: dict[str, str] = {}

    for mod in selected_modules:
        node_id = sanitize_node_id(mod)
        node_id_map[mod] = node_id
        safe_label = sanitize_node_label(mod)
        lines.append(f'    {node_id}["{safe_label}"]')

    lines.append("  end")

    edge_count = 0
    for src, dst in dependencies:
        if edge_count >= max_edges:
            break
        if src in node_id_map and dst in node_id_map and src != dst:
            src_id = node_id_map[src]
            dst_id = node_id_map[dst]
            lines.append(f"  {src_id} --> {dst_id}")
            edge_count += 1

    return "\n".join(lines)
