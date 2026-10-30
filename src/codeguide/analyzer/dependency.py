"""Internal module dependency graph, centrality classification, and cycle detection."""

from collections import defaultdict
from pathlib import PurePosixPath

from codeguide.analyzer.models import (
    CircularDependency,
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    ParsedFile,
)
from codeguide.config.models import AppConfig
from codeguide.scanner.models import Citation


class DependencyAnalyzer:
    """Constructs internal dependency graph and identifies structural anomalies."""

    def __init__(self, config: AppConfig, known_files: list[str]) -> None:
        self.config = config
        self.known_files = set(known_files)
        self._stem_to_file: dict[str, str] = {}
        for kf in known_files:
            p = PurePosixPath(kf)
            stem_key = str(p.with_suffix("")).lower()
            self._stem_to_file[stem_key] = kf
            self._stem_to_file[kf.lower()] = kf

    def build_graph(self, parsed_files: list[ParsedFile]) -> DependencyGraph:
        edges: list[DependencyEdge] = []
        adj: dict[str, set[str]] = defaultdict(set)
        edge_citations: dict[tuple[str, str], Citation] = {}

        for pf in parsed_files:
            source_file = pf.file_path
            for imp in pf.imports:
                target_file = self._resolve_target(source_file, imp.source, imp.is_relative)
                if target_file and target_file != source_file:
                    if target_file not in adj[source_file]:
                        adj[source_file].add(target_file)
                        edge = DependencyEdge(
                            source=source_file, target=target_file, citation=imp.citation
                        )
                        edges.append(edge)
                        edge_citations[(source_file, target_file)] = imp.citation

        # Calculate in-degree and out-degree
        all_nodes = set(self.known_files)
        in_degrees: dict[str, int] = defaultdict(int)
        out_degrees: dict[str, int] = defaultdict(int)

        for edge in edges:
            out_degrees[edge.source] += 1
            in_degrees[edge.target] += 1

        min_in_degree = self.config.analysis.dependencies.core_module_min_in_degree
        core_modules: list[str] = []
        leaf_modules: list[str] = []
        nodes: list[DependencyNode] = []

        for f in sorted(all_nodes):
            in_d = in_degrees[f]
            out_d = out_degrees[f]
            is_core = in_d >= min_in_degree
            is_leaf = (out_d == 0) or (in_d == 0)

            leaf_type: str | None = None
            if in_d == 0 and out_d > 0:
                leaf_type = "entry"
            elif out_d == 0 and in_d > 0:
                leaf_type = "terminal"
            elif in_d == 0 and out_d == 0:
                leaf_type = "isolated"

            if is_core:
                core_modules.append(f)
            if is_leaf:
                leaf_modules.append(f)

            nodes.append(
                DependencyNode(
                    file_path=f,
                    in_degree=in_d,
                    out_degree=out_d,
                    is_core=is_core,
                    is_leaf=is_leaf,
                    leaf_type=leaf_type,
                )
            )

        # Detect circular dependencies
        cycles: list[CircularDependency] = []
        if self.config.analysis.dependencies.detect_circular:
            cycles = self._detect_cycles(adj, edge_citations)

        return DependencyGraph(
            nodes=nodes,
            edges=edges,
            core_modules=core_modules,
            leaf_modules=leaf_modules,
            circular_dependencies=cycles,
        )

    def _resolve_target(
        self, source_path: str, import_source: str, is_relative: bool
    ) -> str | None:
        clean_src = import_source.strip().replace("\\", "/")
        source_posix = PurePosixPath(source_path)

        # Count leading dots for relative imports (. or ..)
        num_dots = 0
        for char in clean_src:
            if char == ".":
                num_dots += 1
            else:
                break

        if is_relative or num_dots > 0:
            parent = source_posix.parent
            remainder = clean_src[num_dots:].lstrip("/")

            cur = parent
            if num_dots > 1:
                for _ in range(num_dots - 1):
                    cur = cur.parent

            for part in remainder.replace(".", "/").split("/"):
                if part and part != ".":
                    if part == "..":
                        cur = cur.parent
                    else:
                        cur = cur / part

            resolved_stem = str(cur).lower()
            return self._stem_to_file.get(resolved_stem)

        for prefix in self.config.analysis.dependencies.internal_import_prefixes:
            if clean_src.startswith(prefix):
                stripped = clean_src.removeprefix(prefix).lstrip("/")
                resolved_stem = str(PurePosixPath(stripped)).lower()
                if resolved_stem in self._stem_to_file:
                    return self._stem_to_file[resolved_stem]

        # Dot-delimited internal modules (e.g. app.models.user)
        slashed = clean_src.replace(".", "/")
        if slashed.lower() in self._stem_to_file:
            return self._stem_to_file[slashed.lower()]

        # Direct file or stem match
        direct = clean_src.lower()
        if direct in self._stem_to_file:
            return self._stem_to_file[direct]

        # Suffix / subpath match across known files
        for stem_k, actual_file in self._stem_to_file.items():
            if stem_k.endswith("/" + direct):
                return actual_file

        return None

    def _detect_cycles(
        self,
        adj: dict[str, set[str]],
        edge_citations: dict[tuple[str, str], Citation],
    ) -> list[CircularDependency]:
        visited: set[str] = set()
        stack: list[str] = []
        in_stack: set[str] = set()
        detected_cycles: list[CircularDependency] = []
        seen_cycle_signatures: set[frozenset[str]] = set()

        def dfs(node: str) -> None:
            visited.add(node)
            stack.append(node)
            in_stack.add(node)

            for neighbor in sorted(adj.get(node, set())):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in in_stack:
                    # Found a cycle from neighbor to current node
                    cycle_start_idx = stack.index(neighbor)
                    cycle_path = stack[cycle_start_idx:] + [neighbor]
                    sig = frozenset(cycle_path)
                    if sig not in seen_cycle_signatures:
                        seen_cycle_signatures.add(sig)
                        citations: list[Citation] = []
                        for i in range(len(cycle_path) - 1):
                            u, v = cycle_path[i], cycle_path[i + 1]
                            cit = edge_citations.get(
                                (u, v),
                                Citation(
                                    file_path=u, start_line=1, end_line=1, snippet=f"{u} -> {v}"
                                ),
                            )
                            citations.append(cit)
                        detected_cycles.append(
                            CircularDependency(cycle=cycle_path, citations=citations)
                        )

            stack.pop()
            in_stack.remove(node)

        for n in sorted(adj.keys()):
            if n not in visited:
                dfs(n)

        return detected_cycles
