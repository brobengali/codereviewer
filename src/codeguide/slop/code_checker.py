"""Codebase slop linter checking restating comments, dead functions, stubs, and docstrings."""

import ast
import re
from pathlib import Path

import vulture  # type: ignore[import-untyped]

from codeguide.common.messages import msg
from codeguide.config.models import AppConfig
from codeguide.slop.models import CodeLintResult, SlopViolation

RESTATING_VERBS = {
    "increment",
    "decrement",
    "return",
    "returns",
    "import",
    "imports",
    "call",
    "calls",
    "set",
    "sets",
    "get",
    "gets",
    "create",
    "creates",
    "assign",
    "assigns",
    "initialize",
    "init",
    "check",
    "checks",
    "pass",
}

STOPWORDS = {"the", "a", "an", "to", "of", "and", "by", "is", "for", "in", "it", "this", "that"}
EXPLANATORY_MARKERS = {
    "pattern",
    "workaround",
    "because",
    "why",
    "note",
    "fix",
    "bug",
    "upstream",
    "due",
    "see",
    "todo",
    "fixme",
    "warning",
    "caution",
}


class CodeSlopChecker:
    """Audits Python codebases for restating comments, dead functions, stubs, and slop."""

    def __init__(self, config: AppConfig, repo_path: Path) -> None:
        self.config = config
        self.repo_path = repo_path.resolve()

    def lint_repo(self) -> CodeLintResult:
        py_files = sorted(
            f
            for f in self.repo_path.rglob("*.py")
            if not any(part.startswith(".") for part in f.parts)
            and not any(
                part in ("__pycache__", "build", "dist", ".venv", "venv") for part in f.parts
            )
        )

        all_calls: set[str] = set()
        command_functions: dict[str, set[str]] = {}
        module_exports: dict[str, set[str]] = {}

        # First pass: collect calls, command decorators, and module __all__ exports
        for f in py_files:
            rel = f.relative_to(self.repo_path).as_posix()
            command_functions[rel] = set()
            module_exports[rel] = set()

            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"), filename=str(f))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            all_calls.add(node.func.id)
                        elif isinstance(node.func, ast.Attribute):
                            all_calls.add(node.func.attr)

                    # Track functions decorated with command decorators
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for dec in node.decorator_list:
                            func = dec.func if isinstance(dec, ast.Call) else dec
                            if (isinstance(func, ast.Attribute) and func.attr == "command") or (
                                isinstance(func, ast.Name) and func.id == "command"
                            ):
                                command_functions[rel].add(node.name)

                    # Track module __all__ assignments
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id == "__all__":
                                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                                    for elt in node.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(
                                            elt.value, str
                                        ):
                                            module_exports[rel].add(elt.value)
            except (OSError, SyntaxError):
                continue

        violations: list[SlopViolation] = []

        # Run file-level AST checks
        for f in py_files:
            file_violations = self.lint_file(f)
            violations.extend(file_violations)

        # Run Vulture across repository for dead functions
        vulture_violations = self._run_vulture_audit(
            py_files, all_calls, command_functions, module_exports
        )
        violations.extend(vulture_violations)

        slop_score = float(len(violations))
        passed = slop_score <= self.config.slop.max_slop_score

        return CodeLintResult(
            repo_path=str(self.repo_path),
            violations=violations,
            files_scanned=len(py_files),
            slop_score=slop_score,
            passed=passed,
        )

    def lint_file(self, file_path: Path) -> list[SlopViolation]:
        violations: list[SlopViolation] = []
        rel_path = file_path.relative_to(self.repo_path).as_posix()

        try:
            content = file_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return violations

        # 1. Restating comments check
        comment_violations = self._check_restating_comments(content, rel_path)
        violations.extend(comment_violations)

        # 2. AST structural checks: bare excepts, stubs, trivial docstrings
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type is None:
                        violations.append(
                            SlopViolation(
                                category="bare_except",
                                file_path=rel_path,
                                line_number=handler.lineno,
                                message=msg(
                                    "errors.bare_except_detected",
                                    line=handler.lineno,
                                    file=rel_path,
                                ),
                                snippet="except:",
                                severity=1.0,
                            )
                        )

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = node.name

                if fn_name.startswith("test_") or (
                    fn_name.startswith("__") and fn_name.endswith("__")
                ):
                    continue

                # Empty or stub body check
                if not self._is_abstract(node):
                    actual_stmts = self._get_non_docstring_statements(node.body)
                    if not actual_stmts:
                        violations.append(
                            SlopViolation(
                                category="stub_body",
                                file_path=rel_path,
                                line_number=node.lineno,
                                message=msg(
                                    "errors.stub_body_detected",
                                    line=node.lineno,
                                    file=rel_path,
                                    function=fn_name,
                                ),
                                snippet=f"def {fn_name}(...): ...",
                                severity=1.0,
                            )
                        )
                    elif len(actual_stmts) == 1 and isinstance(
                        actual_stmts[0], (ast.Pass, ast.Expr)
                    ):
                        stmt = actual_stmts[0]
                        if isinstance(stmt, ast.Pass) or (
                            isinstance(stmt, ast.Expr)
                            and isinstance(stmt.value, ast.Constant)
                            and stmt.value.value is ...
                        ):
                            violations.append(
                                SlopViolation(
                                    category="stub_body",
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    message=msg(
                                        "errors.stub_body_detected",
                                        line=node.lineno,
                                        file=rel_path,
                                        function=fn_name,
                                    ),
                                    snippet=f"def {fn_name}(...): pass",
                                    severity=1.0,
                                )
                            )

                # Docstring on trivial function check
                docstring = ast.get_docstring(node, clean=True)
                actual_stmts = self._get_non_docstring_statements(node.body)
                if docstring and len(actual_stmts) == 1:
                    single_stmt = actual_stmts[0]
                    if isinstance(single_stmt, ast.Return):
                        doc_lines = docstring.strip().splitlines()
                        is_trivial_repetition = (
                            len(doc_lines) > 1
                            or docstring.lower().strip(".").replace(" ", "_") == fn_name.lower()
                            or f"get {fn_name[4:]}" in docstring.lower()
                        )
                        if is_trivial_repetition:
                            violations.append(
                                SlopViolation(
                                    category="trivial_docstring",
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    message=msg(
                                        "errors.trivial_docstring_detected",
                                        line=node.lineno,
                                        file=rel_path,
                                        function=fn_name,
                                    ),
                                    snippet=docstring.splitlines()[0],
                                    severity=1.0,
                                )
                            )

        return violations

    def _check_restating_comments(self, content: str, rel_path: str) -> list[SlopViolation]:
        violations: list[SlopViolation] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            line_no = idx + 1
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue

            comment_body = stripped.lstrip("#").strip()
            if not comment_body:
                continue

            # Ignore directives, pragmas, links, or quotation marks
            if any(
                comment_body.startswith(p)
                for p in ("noqa", "type:", "nosec", "pragma:", "!", "http", "TODO", "FIXME")
            ):
                continue

            # If comment contains quotation marks or colons, it is explanatory text
            if '"' in comment_body or "'" in comment_body or ":" in comment_body:
                continue

            # Find next non-empty, non-comment code line
            next_code_line: str | None = None
            for probe_idx in range(idx + 1, min(len(lines), idx + 4)):
                probe = lines[probe_idx].strip()
                if probe and not probe.startswith("#"):
                    next_code_line = probe
                    break

            if not next_code_line:
                continue

            c_words = [w.lower() for w in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", comment_body)]
            code_words = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", next_code_line.lower()))

            if not c_words or len(c_words) > 5:
                continue

            # Explanatory words mean comment explains context/why
            if any(w in EXPLANATORY_MARKERS for w in c_words):
                continue

            non_stopwords = [w for w in c_words if w not in STOPWORDS]
            if not non_stopwords:
                continue

            has_verb = any(w in RESTATING_VERBS for w in non_stopwords)
            all_in_code = all(w in code_words or w in RESTATING_VERBS for w in non_stopwords)
            is_increment = "increment" in non_stopwords and (
                "+=" in next_code_line or "+ 1" in next_code_line
            )
            is_return = "return" in non_stopwords and next_code_line.startswith("return")

            if (has_verb and all_in_code) or is_increment or (is_return and all_in_code):
                violations.append(
                    SlopViolation(
                        category="restating_comment",
                        file_path=rel_path,
                        line_number=line_no,
                        message=msg(
                            "errors.restating_comment_detected",
                            line=line_no,
                            file=rel_path,
                            comment=comment_body,
                        ),
                        snippet=stripped,
                        severity=1.0,
                    )
                )

        return violations

    def _run_vulture_audit(
        self,
        py_files: list[Path],
        all_repo_calls: set[str],
        command_functions: dict[str, set[str]],
        module_exports: dict[str, set[str]],
    ) -> list[SlopViolation]:
        violations: list[SlopViolation] = []
        v = vulture.Vulture(verbose=False)

        try:
            v.scavenge([str(self.repo_path)])
            for item in v.get_unused_code():
                if item.typ == "function":
                    fn_name = item.name
                    if fn_name.startswith("test_") or fn_name.startswith("__"):
                        continue

                    # Resolve relative path for the item
                    item_path = Path(item.filename).resolve()
                    try:
                        rel = item_path.relative_to(self.repo_path).as_posix()
                    except ValueError:
                        continue

                    # Exclude CLI commands, explicit __all__ exports, or cross-repo calls
                    if rel in command_functions and fn_name in command_functions[rel]:
                        continue
                    if rel in module_exports and fn_name in module_exports[rel]:
                        continue
                    if fn_name in all_repo_calls:
                        continue

                    violations.append(
                        SlopViolation(
                            category="dead_function",
                            file_path=rel,
                            line_number=item.first_lineno,
                            message=msg(
                                "errors.dead_function_detected",
                                line=item.first_lineno,
                                file=rel,
                                function=fn_name,
                            ),
                            snippet=f"def {fn_name}(...)",
                            severity=1.0,
                        )
                    )
        except (OSError, SyntaxError):
            pass

        return violations

    def _is_abstract(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "abstractmethod":
                return True
            if isinstance(decorator, ast.Attribute) and decorator.attr == "abstractmethod":
                return True
        return False

    def _get_non_docstring_statements(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if not body:
            return []
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return body[1:]
        return body
