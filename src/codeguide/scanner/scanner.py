"""Repository scanner producing typed, citation-backed ScanResult structures."""

import fnmatch
import os
from pathlib import Path

from codeguide.config.models import AppConfig
from codeguide.scanner.gitignore import GitIgnoreFilter
from codeguide.scanner.models import (
    DetectedLanguage,
    DetectedSymbol,
    FileNode,
    KeyDocument,
    ScanResult,
)
from codeguide.scanner.rules import RuleEngine


class RepositoryScanner:
    """Walks an isolated repository, executes rule-based detections, and builds a file tree."""

    def __init__(
        self,
        repo_root: Path,
        config: AppConfig,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.config = config
        self.rule_engine = rule_engine or RuleEngine.load(config)
        self.filter = GitIgnoreFilter(self.repo_root, config)

    def scan(self) -> ScanResult:
        """Execute full repository scan and return typed, JSON-serializable artifact."""
        discovered_files: list[str] = []
        file_contents: dict[str, str] = {}
        file_lines: dict[str, list[str]] = {}
        file_sizes: dict[str, int] = {}
        file_langs: dict[str, str] = {}

        total_lines = 0
        total_size = 0
        documents: list[KeyDocument] = []

        # 1. Traversal and content acquisition
        for root_dir, dirs, files in os.walk(self.repo_root):
            rel_dir = Path(root_dir).relative_to(self.repo_root).as_posix()
            if rel_dir == ".":
                rel_dir = ""

            # In-place directory pruning
            dirs[:] = [
                d
                for d in dirs
                if not self.filter.is_ignored(f"{rel_dir}/{d}" if rel_dir else d, is_dir=True)
            ]

            for fname in files:
                rel_file = f"{rel_dir}/{fname}" if rel_dir else fname
                if self.filter.is_ignored(rel_file, is_dir=False):
                    continue

                abs_file = Path(root_dir) / fname
                if self.filter.is_binary_file(abs_file):
                    continue

                try:
                    fsize = abs_file.stat().st_size
                except OSError:
                    continue

                if fsize > self.config.analysis.max_file_size_bytes:
                    continue

                try:
                    text = abs_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                lines = text.splitlines()
                first_line = lines[0] if lines else ""
                lang = self.rule_engine.detect_language(fname, first_line)

                discovered_files.append(rel_file)
                file_contents[rel_file] = text
                file_lines[rel_file] = lines
                file_sizes[rel_file] = fsize
                if lang:
                    file_langs[rel_file] = lang

                total_lines += len(lines)
                total_size += fsize

                # Collect documentation, CI, and container definitions as raw documents
                doc_cat = self._classify_document(rel_file)
                if doc_cat:
                    documents.append(
                        KeyDocument(
                            path=rel_file,
                            category=doc_cat,
                            content=text,
                            line_count=len(lines),
                        )
                    )

        # 2. Extract code symbols across all read files
        all_entry_points: list[DetectedSymbol] = []
        all_routes: list[DetectedSymbol] = []
        all_db_models: list[DetectedSymbol] = []
        all_env_vars: list[DetectedSymbol] = []

        for rel_file in discovered_files:
            lines = file_lines[rel_file]
            eps, rts, mdls, evs = self.rule_engine.extract_symbols(rel_file, lines)
            all_entry_points.extend(eps)
            all_routes.extend(rts)
            all_db_models.extend(mdls)
            all_env_vars.extend(evs)

        # 3. Detect frameworks, package managers, and test tools
        frameworks = self.rule_engine.match_frameworks(discovered_files, file_contents)
        package_managers = self.rule_engine.match_package_managers(discovered_files, file_contents)
        test_tools = self.rule_engine.match_test_tools(discovered_files, file_contents)

        # 4. Aggregate language statistics
        lang_counts: dict[str, dict[str, int]] = {}
        for rel_file, lang_name in file_langs.items():
            entry = lang_counts.setdefault(lang_name, {"files": 0, "lines": 0})
            entry["files"] += 1
            entry["lines"] += len(file_lines[rel_file])

        languages_summary: list[DetectedLanguage] = []
        for lname, data in lang_counts.items():
            pct = round((data["lines"] / total_lines * 100.0) if total_lines > 0 else 0.0, 2)
            languages_summary.append(
                DetectedLanguage(
                    name=lname,
                    files_count=data["files"],
                    lines_count=data["lines"],
                    percentage=pct,
                )
            )
        languages_summary.sort(key=lambda item: item.lines_count, reverse=True)

        # 5. Build file tree with importance ratings
        entrypoint_files = {ep.citation.file_path for ep in all_entry_points}
        route_files = {rt.citation.file_path for rt in all_routes}
        db_model_files = {db.citation.file_path for db in all_db_models}
        doc_files = {doc.path for doc in documents}

        file_tree = self._build_file_tree(
            discovered_files=discovered_files,
            file_lines=file_lines,
            file_sizes=file_sizes,
            file_langs=file_langs,
            entrypoint_files=entrypoint_files,
            route_files=route_files,
            db_model_files=db_model_files,
            doc_files=doc_files,
        )

        return ScanResult(
            repo_name=self.repo_root.name,
            repo_path=str(self.repo_root),
            total_files=len(discovered_files),
            total_lines=total_lines,
            total_size_bytes=total_size,
            languages=languages_summary,
            frameworks=frameworks,
            package_managers=package_managers,
            test_tools=test_tools,
            entry_points=all_entry_points,
            routes=all_routes,
            db_models=all_db_models,
            env_vars=all_env_vars,
            file_tree=file_tree,
            documents=documents,
        )

    def _classify_document(self, rel_path: str) -> str | None:
        fname = Path(rel_path).name
        for pat in self.config.analysis.documentation_patterns:
            if fnmatch.fnmatch(fname, pat):
                return "documentation"
        for pat in self.config.analysis.ci_patterns:
            if fnmatch.fnmatch(rel_path, pat):
                return "ci"
        for pat in self.config.analysis.build_file_patterns:
            if fnmatch.fnmatch(fname, pat):
                return "build"
        return None

    def _calculate_importance_score(
        self,
        rel_path: str,
        lines_count: int,
        is_entrypoint: bool,
        is_route: bool,
        is_model: bool,
        is_doc: bool,
    ) -> float:
        w = self.config.analysis.importance_weights
        score = w.base_score

        if is_entrypoint:
            score += w.entrypoint_bonus
        if is_route:
            score += w.route_bonus
        if is_model:
            score += w.db_model_bonus
        if is_doc:
            score += w.documentation_bonus
        if "/" not in rel_path:
            score += w.root_bonus

        lines_bonus = min(lines_count * w.lines_scale, w.max_lines_bonus)
        score += lines_bonus

        return round(score, 2)

    def _build_file_tree(
        self,
        discovered_files: list[str],
        file_lines: dict[str, list[str]],
        file_sizes: dict[str, int],
        file_langs: dict[str, str],
        entrypoint_files: set[str],
        route_files: set[str],
        db_model_files: set[str],
        doc_files: set[str],
    ) -> FileNode:
        root_node = FileNode(
            path="",
            is_dir=True,
            line_count=0,
            size_bytes=0,
            importance_score=0.0,
            language=None,
            children=[],
        )

        for rel_file in sorted(discovered_files):
            parts = rel_file.split("/")
            current = root_node

            for idx, _part in enumerate(parts):
                is_file = idx == len(parts) - 1
                curr_path = "/".join(parts[: idx + 1])

                existing = next(
                    (child for child in current.children if child.path == curr_path),
                    None,
                )
                if existing is None:
                    if is_file:
                        lcount = len(file_lines[rel_file])
                        score = self._calculate_importance_score(
                            rel_path=rel_file,
                            lines_count=lcount,
                            is_entrypoint=rel_file in entrypoint_files,
                            is_route=rel_file in route_files,
                            is_model=rel_file in db_model_files,
                            is_doc=rel_file in doc_files,
                        )
                        node = FileNode(
                            path=curr_path,
                            is_dir=False,
                            line_count=lcount,
                            size_bytes=file_sizes[rel_file],
                            importance_score=score,
                            language=file_langs.get(rel_file),
                            children=[],
                        )
                    else:
                        node = FileNode(
                            path=curr_path,
                            is_dir=True,
                            line_count=0,
                            size_bytes=0,
                            importance_score=0.0,
                            language=None,
                            children=[],
                        )
                    current.children.append(node)
                    current = node
                else:
                    current = existing

        return root_node
