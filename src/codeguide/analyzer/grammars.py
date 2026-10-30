"""Dynamic tree-sitter grammar and query loader."""

import importlib
import logging
import tomllib
from pathlib import Path
from typing import Any

import tree_sitter

from codeguide.config.models import AppConfig

logger = logging.getLogger("codeguide.analyzer.grammars")


class GrammarRegistry:
    """Manages loaded tree-sitter languages and compiled queries."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._languages: dict[str, tree_sitter.Language] = {}
        self._parsers: dict[str, tree_sitter.Parser] = {}
        self._queries: dict[str, dict[str, tree_sitter.Query]] = {}
        self._extension_map: dict[str, str] = {}
        self._query_rules: dict[str, Any] = {}
        self._load_query_rules()
        self._initialize_grammars()

    def _load_query_rules(self) -> None:
        q_path = Path(self.config.paths.queries_file)
        if not q_path.is_file():
            q_path = (
                Path(__file__).resolve().parent.parent
                / "data"
                / "rules"
                / "tree_sitter_queries.toml"
            )
        if q_path.is_file():
            with q_path.open("rb") as f:
                self._query_rules = tomllib.load(f)

    def _initialize_grammars(self) -> None:
        for lang_name, grammar_cfg in self.config.analysis.grammars.items():
            for ext in grammar_cfg.extensions:
                self._extension_map[ext.lower()] = lang_name

            try:
                mod = importlib.import_module(grammar_cfg.package)
                lang_factory = getattr(mod, grammar_cfg.function)
                lang_obj = tree_sitter.Language(lang_factory())
                self._languages[lang_name] = lang_obj
                self._parsers[lang_name] = tree_sitter.Parser(lang_obj)
                self._compile_queries_for_language(lang_name, lang_obj)
            except (ImportError, AttributeError, Exception) as exc:
                logger.debug("Tree-sitter grammar unavailable for %s: %s", lang_name, exc)

    def _compile_queries_for_language(self, lang_name: str, language: tree_sitter.Language) -> None:
        raw_queries = self._query_rules.get("queries", {}).get(lang_name, {})
        compiled: dict[str, tree_sitter.Query] = {}
        for query_kind, query_str in raw_queries.items():
            try:
                compiled[query_kind] = tree_sitter.Query(language, query_str)
            except Exception as exc:
                logger.debug(
                    "Failed compiling tree-sitter %s query for %s: %s", query_kind, lang_name, exc
                )
        self._queries[lang_name] = compiled

    def get_language_for_extension(self, extension: str) -> str | None:
        return self._extension_map.get(extension.lower())

    def get_parser(self, lang_name: str) -> tree_sitter.Parser | None:
        return self._parsers.get(lang_name)

    def get_queries(self, lang_name: str) -> dict[str, tree_sitter.Query]:
        return self._queries.get(lang_name, {})

    def get_fallback_patterns(self, lang_name: str) -> dict[str, str]:
        fallbacks = self._query_rules.get("fallbacks", {})
        res = dict(fallbacks.get("generic", {}))
        if lang_name in fallbacks:
            res.update(fallbacks[lang_name])
        return res
