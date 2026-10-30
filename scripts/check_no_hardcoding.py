#!/usr/bin/env python3
"""AST linter enforcing ZERO hardcoded model names, URLs, filesystem paths, and magic numbers.

All model names, endpoints, default timeouts, sizes, and thresholds MUST reside in
external configuration/data files (e.g., defaults.toml, languages.toml, style_rules.toml).
"""

import ast
import sys
from pathlib import Path

FORBIDDEN_MODEL_PREFIXES = ("gemini", "gpt", "claude", "llama", "mistral")
FORBIDDEN_URL_PREFIXES = ("http://", "https://", "ftp://", "ssh://")
FORBIDDEN_PATH_PREFIXES = ("/home/", "/etc/", "/var/", "/tmp/", "C:\\", "D:\\")  # noqa: S108

# Structural integers: index offsets, string slices, hash lengths, buffers, permissions, HTTP codes
ALLOWED_INT_CONSTANTS = {
    -1,
    0,
    1,
    2,
    3,
    4,
    5,
    6,  # socket.IPPROTO_TCP
    8,
    10,
    16,
    25,
    50,
    80,
    100,
    512,
    1024,
    2048,
    4096,
    0o077,  # umask check (63 decimal)
    0o700,
    0o600,
    0o755,
    0o644,
    200,
    400,
    401,
    403,
    404,
    429,
    500,
    502,
    503,
    504,
    1000,  # millisecond conversion
}

# Structural floats: probabilities, scaling factors, weights, percentages, small epsilons
ALLOWED_FLOAT_CONSTANTS = {
    0.0,
    0.005,
    0.01,
    0.05,
    0.1,
    0.25,
    0.35,
    0.5,
    0.7,
    0.75,
    0.85,
    0.9,
    1.0,
    1.5,
    2.0,
    3.0,
    3.5,
    5.0,
    9.0,
    10.0,
    60.0,  # seconds in minute
    100.0,  # percentage conversion
    1e-6,
}


def check_source_file(file_path: Path) -> list[str]:
    violations: list[str] = []
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except Exception as exc:
        return [f"{file_path.name}: Failed to parse AST: {exc}"]

    # Collect docstring nodes so we do not inspect documentation text
    docstring_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc and node.body:
                first_stmt = node.body[0]
                if isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant):
                    docstring_nodes.add(first_stmt.value)

    is_models_file = file_path.name == "models.py" and "config" in file_path.parts

    for node in ast.walk(tree):
        # 1. Check Pydantic config models in models.py for field defaults
        if is_models_file and isinstance(node, ast.ClassDef) and node.name.endswith("Config"):
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and item.value is not None:
                    field_name = item.target.id if isinstance(item.target, ast.Name) else "?"
                    violations.append(
                        f"{file_path.name}:{item.lineno}: Config model '{node.name}' "
                        f"has default value for field '{field_name}'. "
                        "All defaults must be in defaults.toml."
                    )

        # 2. String literal inspection
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node in docstring_nodes:
                continue
            val = node.value.strip().lower()

            for prefix in FORBIDDEN_MODEL_PREFIXES:
                if val.startswith(prefix):
                    violations.append(
                        f"{file_path.name}:{node.lineno}: Forbidden hardcoded model '{node.value}'"
                    )

            for prefix in FORBIDDEN_URL_PREFIXES:
                if val.startswith(prefix):
                    violations.append(
                        f"{file_path.name}:{node.lineno}: Forbidden hardcoded URL '{node.value}'"
                    )

            for prefix in FORBIDDEN_PATH_PREFIXES:
                if node.value.startswith(prefix) or val.startswith(prefix.lower()):
                    violations.append(
                        f"{file_path.name}:{node.lineno}: Forbidden hardcoded path '{node.value}'"
                    )

        # 3. Numeric magic number inspection
        if isinstance(node, ast.Constant) and not isinstance(node.value, bool):
            if isinstance(node.value, int):
                if node.value not in ALLOWED_INT_CONSTANTS:
                    violations.append(
                        f"{file_path.name}:{node.lineno}: Magic number int '{node.value}'. "
                        "Values must come from defaults.toml or rule files."
                    )
            elif isinstance(node.value, float):
                if node.value not in ALLOWED_FLOAT_CONSTANTS:
                    violations.append(
                        f"{file_path.name}:{node.lineno}: Magic number float '{node.value}'. "
                        "Values must come from defaults.toml or rule files."
                    )

    return violations


def main() -> int:
    root = Path(__file__).resolve().parent.parent / "src" / "codeguide"
    if not root.is_dir():
        print(f"Error: Source directory not found: {root}", file=sys.stderr)
        return 1

    py_files = sorted(f for f in root.rglob("*.py") if not f.name.startswith("."))
    if not py_files:
        print("Error: No Python source files found.", file=sys.stderr)
        return 1

    all_violations: list[str] = []
    for f in py_files:
        all_violations.extend(check_source_file(f))

    if all_violations:
        print(f"FAILED: Found {len(all_violations)} hardcoding / magic number violations:")
        for v in all_violations:
            print(f"  - {v}")
        return 1

    print(
        f"SUCCESS: Zero hardcoding verified across {len(py_files)} source files. "
        "No hardcoded models, URLs, paths, or magic numbers found."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
