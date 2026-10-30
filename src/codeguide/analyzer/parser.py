"""Code structure parser using Tree-Sitter AST with graceful regex fallback."""

import logging
import re

import tree_sitter

from codeguide.analyzer.grammars import GrammarRegistry
from codeguide.analyzer.models import ImportStatement, ParsedFile, SymbolDefinition
from codeguide.scanner.models import Citation

logger = logging.getLogger("codeguide.analyzer.parser")


class CodeParser:
    """Parses code files using tree-sitter queries or regex fallbacks."""

    def __init__(self, registry: GrammarRegistry) -> None:
        self.registry = registry

    def parse_file(self, file_path: str, content: str, language: str) -> ParsedFile:
        lang_key = language.lower()
        parser = self.registry.get_parser(lang_key)
        lines = content.splitlines()
        lines_count = len(lines)

        if parser is not None:
            try:
                return self._parse_with_tree_sitter(
                    file_path, content, lang_key, parser, lines_count
                )
            except Exception as exc:
                logger.debug("Tree-sitter parse failed for %s (%s): %s", file_path, lang_key, exc)

        return self._parse_with_regex(file_path, lines, lang_key, lines_count)

    def _parse_with_tree_sitter(
        self,
        file_path: str,
        content: str,
        language: str,
        parser: tree_sitter.Parser,
        lines_count: int,
    ) -> ParsedFile:
        source_bytes = content.encode("utf-8")
        tree = parser.parse(source_bytes)
        has_errors = tree.root_node.has_error
        error_line = self._locate_error_line(tree.root_node) if has_errors else None

        symbols: list[SymbolDefinition] = []
        imports: list[ImportStatement] = []
        queries = self.registry.get_queries(language)

        if "functions" in queries:
            symbols.extend(
                self._extract_query_symbols(
                    file_path, queries["functions"], tree.root_node, "function"
                )
            )
        if "classes" in queries:
            symbols.extend(
                self._extract_query_symbols(file_path, queries["classes"], tree.root_node, "class")
            )
        if "imports" in queries:
            imports.extend(
                self._extract_query_imports(file_path, queries["imports"], tree.root_node)
            )

        # If tree-sitter had errors or extracted nothing, attempt regex recovery as supplement
        if has_errors or (not symbols and not imports and lines_count > 0):
            fallback_res = self._parse_with_regex(
                file_path, content.splitlines(), language, lines_count
            )
            existing_syms = {s.name for s in symbols}
            for sym in fallback_res.symbols:
                if sym.name not in existing_syms:
                    symbols.append(sym)
            existing_imports = {imp.source for imp in imports}
            for imp in fallback_res.imports:
                if imp.source not in existing_imports:
                    imports.append(imp)

        return ParsedFile(
            file_path=file_path,
            language=language,
            parser_used="tree-sitter",
            has_errors=has_errors,
            error_line=error_line,
            symbols=symbols,
            imports=imports,
            lines_count=lines_count,
        )

    def _locate_error_line(self, node: tree_sitter.Node) -> int | None:
        if not node.has_error:
            return None
        for child in node.children:
            if child.has_error:
                res = self._locate_error_line(child)
                if res is not None:
                    return res
        return node.start_point.row + 1

    def _extract_query_symbols(
        self,
        file_path: str,
        query: tree_sitter.Query,
        root: tree_sitter.Node,
        kind: str,
    ) -> list[SymbolDefinition]:
        symbols: list[SymbolDefinition] = []
        cursor = tree_sitter.QueryCursor(query)
        matches = list(cursor.matches(root))
        for _, captures in matches:
            name_nodes = captures.get("name", [])
            def_nodes = captures.get("def", name_nodes)
            if not name_nodes or not def_nodes:
                continue

            name_raw = name_nodes[0].text or b""
            name = name_raw.decode("utf-8", errors="replace")
            def_node = def_nodes[0]
            start_line = def_node.start_point.row + 1
            end_line = def_node.end_point.row + 1

            snippet_raw = def_node.text or b""
            citation = Citation(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet_raw.decode("utf-8", errors="replace")[:100],
            )
            symbols.append(SymbolDefinition(name=name, kind=kind, citation=citation))
        return symbols

    def _extract_query_imports(
        self,
        file_path: str,
        query: tree_sitter.Query,
        root: tree_sitter.Node,
    ) -> list[ImportStatement]:
        imports: list[ImportStatement] = []
        cursor = tree_sitter.QueryCursor(query)
        matches = list(cursor.matches(root))
        for _, captures in matches:
            source: str | None = None
            is_relative = False

            if "import_source" in captures:
                raw_src = (
                    (captures["import_source"][0].text or b"")
                    .decode("utf-8", errors="replace")
                    .strip("\"'")
                )
                source = raw_src
                is_relative = source.startswith(".")
            elif "req_source" in captures:
                raw_src = (
                    (captures["req_source"][0].text or b"")
                    .decode("utf-8", errors="replace")
                    .strip("\"'")
                )
                source = raw_src
                is_relative = source.startswith(".")
            elif "rel_module" in captures:
                source = (captures["rel_module"][0].text or b"").decode("utf-8", errors="replace")
                is_relative = True
            elif "module_name" in captures:
                source = (captures["module_name"][0].text or b"").decode("utf-8", errors="replace")
            elif "import" in captures:
                source = (captures["import"][0].text or b"").decode("utf-8", errors="replace")

            if source:
                node_list = (
                    captures.get("import_source")
                    or captures.get("req_source")
                    or captures.get("rel_module")
                    or captures.get("module_name")
                    or captures.get("import")
                )
                if not node_list:
                    continue
                target_node = node_list[0]
                line = target_node.start_point.row + 1
                citation = Citation(
                    file_path=file_path,
                    start_line=line,
                    end_line=line,
                    snippet=source,
                )
                imports.append(
                    ImportStatement(
                        source=source,
                        imported_symbols=[],
                        is_relative=is_relative,
                        citation=citation,
                    )
                )
        return imports

    def _parse_with_regex(
        self,
        file_path: str,
        lines: list[str],
        language: str,
        lines_count: int,
    ) -> ParsedFile:
        symbols: list[SymbolDefinition] = []
        imports: list[ImportStatement] = []
        patterns = self.registry.get_fallback_patterns(language)

        fn_re = re.compile(patterns["functions"]) if "functions" in patterns else None
        cls_re = re.compile(patterns["classes"]) if "classes" in patterns else None
        imp_re = re.compile(patterns["imports"]) if "imports" in patterns else None

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if fn_re:
                fn_m = fn_re.search(line)
                if fn_m:
                    name = next((g for g in fn_m.groups() if g), None)
                    if name:
                        symbols.append(
                            SymbolDefinition(
                                name=name,
                                kind="function",
                                citation=Citation(
                                    file_path=file_path,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=stripped,
                                ),
                            )
                        )
            if cls_re:
                cls_m = cls_re.search(line)
                if cls_m:
                    name = next((g for g in cls_m.groups() if g), None)
                    if name:
                        symbols.append(
                            SymbolDefinition(
                                name=name,
                                kind="class",
                                citation=Citation(
                                    file_path=file_path,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=stripped,
                                ),
                            )
                        )
            if imp_re:
                imp_m = imp_re.search(line)
                if imp_m:
                    src = next((g for g in imp_m.groups() if g), None)
                    if src:
                        is_rel = src.startswith(".")
                        imports.append(
                            ImportStatement(
                                source=src,
                                imported_symbols=[],
                                is_relative=is_rel,
                                citation=Citation(
                                    file_path=file_path,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=stripped,
                                ),
                            )
                        )

        return ParsedFile(
            file_path=file_path,
            language=language,
            parser_used="regex",
            has_errors=False,
            error_line=None,
            symbols=symbols,
            imports=imports,
            lines_count=lines_count,
        )
