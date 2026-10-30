"""Documentation generation engine producing grounded onboarding docs and interactive dashboards."""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from codeguide.analyzer.models import AnalysisResult
from codeguide.config.models import AppConfig
from codeguide.generator.grounding import CitationGrounder
from codeguide.generator.html_escaper import safe_json_embed
from codeguide.generator.mermaid import build_mermaid_architecture
from codeguide.generator.models import (
    FeatureFlow,
    FeatureFlowStep,
    FolderGuideItem,
    GlossaryTerm,
    GotchaItem,
    OnboardingContext,
    SetupStep,
    StarterTask,
    TechStackItem,
)
from codeguide.generator.writer import SafeOutputWriter
from codeguide.scanner.models import ScanResult


class DocumentationGenerator:
    """Orchestrates structured onboarding and interactive dashboard generation."""

    def __init__(self, config: AppConfig, repo_root: Path) -> None:
        self.config = config
        self.repo_root = repo_root.resolve()
        self.unclear = config.style.unclear_marker

        # Configure Jinja2 environment loading from external templates directory
        template_base = Path(config.paths.templates_dir)
        if not template_base.is_absolute():
            template_base = (Path.cwd() / template_base).resolve()

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_base)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.grounder = CitationGrounder(self.repo_root, unclear_marker=self.unclear)
        self.writer = SafeOutputWriter(Path(config.paths.output_dir))

    def _extract_purpose(self, scan_result: ScanResult) -> tuple[str, str]:
        for doc in scan_result.documents:
            if "readme" in doc.path.lower():
                lines = doc.content.splitlines()
                for idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and len(stripped) > 10:
                        return stripped, f"{doc.path}:{idx}"
        return "unclear", self.unclear

    def _build_tech_stack(self, scan_result: ScanResult) -> list[TechStackItem]:
        items: list[TechStackItem] = []
        for lang in scan_result.languages:
            items.append(
                TechStackItem(
                    name=lang.name,
                    category="Language",
                    citation=self.unclear,
                )
            )

        for fw in scan_result.frameworks:
            citation_str = (
                f"{fw.evidence[0].file_path}:{fw.evidence[0].start_line}-{fw.evidence[0].end_line}"
                if fw.evidence
                else self.unclear
            )
            items.append(
                TechStackItem(
                    name=fw.name,
                    category="Framework",
                    citation=citation_str,
                )
            )

        for pm in scan_result.package_managers:
            citation_str = (
                f"{pm.evidence[0].file_path}:{pm.evidence[0].start_line}-{pm.evidence[0].end_line}"
                if pm.evidence
                else self.unclear
            )
            items.append(
                TechStackItem(
                    name=pm.name,
                    category="Package Manager",
                    citation=citation_str,
                )
            )

        for tt in scan_result.test_tools:
            citation_str = (
                f"{tt.evidence[0].file_path}:{tt.evidence[0].start_line}-{tt.evidence[0].end_line}"
                if tt.evidence
                else self.unclear
            )
            items.append(
                TechStackItem(
                    name=tt.name,
                    category="Test Tool",
                    citation=citation_str,
                )
            )

        return items

    def _build_folder_guide(self, scan_result: ScanResult) -> list[FolderGuideItem]:
        guide_items: list[FolderGuideItem] = []
        for child in scan_result.file_tree.children:
            if child.is_dir:
                first_file = next(
                    (c.path for c in child.children if not c.is_dir),
                    f"{child.path}/__init__.py",
                )
                purpose = (
                    f"Module directory containing {child.line_count} "
                    "lines of code across subpackages."
                )
                guide_items.append(
                    FolderGuideItem(
                        path=child.path,
                        purpose=purpose,
                        citation=f"{first_file}:1",
                    )
                )
        return guide_items

    def _build_feature_flows(
        self, scan_result: ScanResult, analysis_result: AnalysisResult
    ) -> list[FeatureFlow]:
        flows: list[FeatureFlow] = []

        # Flow 1: Primary entrypoint and execution path
        if scan_result.entry_points:
            ep = scan_result.entry_points[0]
            steps = [
                FeatureFlowStep(
                    order=1,
                    description=f"Invocation begins at entrypoint function `{ep.name}`.",
                    citation=f"{ep.citation.file_path}:{ep.citation.start_line}",
                )
            ]
            if analysis_result.dependency_graph.core_modules:
                core_mod = analysis_result.dependency_graph.core_modules[0]
                steps.append(
                    FeatureFlowStep(
                        order=2,
                        description=(
                            f"Execution transitions into core coordination module `{core_mod}`."
                        ),
                        citation=f"{core_mod}:1",
                    )
                )
            flows.append(
                FeatureFlow(
                    name="Command Execution Flow",
                    description=(
                        "Standard command dispatch from CLI entrypoint through core "
                        "application engine."
                    ),
                    steps=steps,
                )
            )

        # Flow 2: Route or Symbol handling flow
        if scan_result.routes:
            route = scan_result.routes[0]
            flows.append(
                FeatureFlow(
                    name="Request Handling Flow",
                    description=f"HTTP endpoint dispatch for route `{route.name}`.",
                    steps=[
                        FeatureFlowStep(
                            order=1,
                            description=f"Incoming request matched against route `{route.name}`.",
                            citation=f"{route.citation.file_path}:{route.citation.start_line}",
                        )
                    ],
                )
            )
        elif analysis_result.symbols:
            sym = analysis_result.symbols[0]
            flows.append(
                FeatureFlow(
                    name="Core Model Transformation Flow",
                    description=f"Domain entity construction and operation for `{sym.name}`.",
                    steps=[
                        FeatureFlowStep(
                            order=1,
                            description=(
                                f"Entity definition and lifecycle initialized for `{sym.name}`."
                            ),
                            citation=f"{sym.citation.file_path}:{sym.citation.start_line}",
                        )
                    ],
                )
            )

        return flows

    def _build_setup_steps(self, scan_result: ScanResult) -> list[SetupStep]:
        steps: list[SetupStep] = []
        for doc in scan_result.documents:
            if "pyproject.toml" in doc.path:
                steps.append(
                    SetupStep(
                        step_number=1,
                        instruction=(
                            "Install project dependencies defined in pyproject manifest "
                            "using virtual environment."
                        ),
                        citation=f"{doc.path}:1",
                    )
                )
            elif "package.json" in doc.path:
                steps.append(
                    SetupStep(
                        step_number=1,
                        instruction="Install npm package dependencies via package manifest.",
                        citation=f"{doc.path}:1",
                    )
                )

        if not steps and scan_result.documents:
            first_doc = scan_result.documents[0]
            steps.append(
                SetupStep(
                    step_number=1,
                    instruction=f"Consult setup instructions documented in `{first_doc.path}`.",
                    citation=f"{first_doc.path}:1",
                )
            )

        return steps

    def _build_glossary(self, analysis_result: AnalysisResult) -> list[GlossaryTerm]:
        terms: list[GlossaryTerm] = []
        for sym in analysis_result.symbols:
            if sym.kind in ("class", "interface", "struct"):
                terms.append(
                    GlossaryTerm(
                        term=sym.name,
                        definition=(
                            f"Architectural entity declared as {sym.kind} in "
                            f"{sym.citation.file_path}."
                        ),
                        citation=f"{sym.citation.file_path}:{sym.citation.start_line}",
                    )
                )
            if len(terms) >= 10:
                break
        return terms

    def _build_starter_tasks(
        self, scan_result: ScanResult, analysis_result: AnalysisResult
    ) -> list[StarterTask]:
        tasks: list[StarterTask] = []
        first_test = next(
            (
                s.citation.file_path
                for s in analysis_result.symbols
                if "test" in s.citation.file_path.lower()
            ),
            None,
        )
        first_ep = scan_result.entry_points[0] if scan_result.entry_points else None
        first_core = (
            analysis_result.dependency_graph.core_modules[0]
            if analysis_result.dependency_graph.core_modules
            else None
        )

        test_cit = f"{first_test}:1" if first_test else self.unclear
        tasks.append(
            StarterTask(
                day=1,
                title="Verify Environment and Test Suite",
                description=(
                    "Run local test runner to verify environment reproducibility "
                    "against existing tests."
                ),
                citation=test_cit,
            )
        )

        ep_cit = (
            f"{first_ep.citation.file_path}:{first_ep.citation.start_line}"
            if first_ep
            else self.unclear
        )
        tasks.append(
            StarterTask(
                day=2,
                title="Trace Execution Entrypoint",
                description=(
                    "Follow execution path starting from primary CLI or application entrypoint."
                ),
                citation=ep_cit,
            )
        )

        core_cit = f"{first_core}:1" if first_core else self.unclear
        tasks.append(
            StarterTask(
                day=3,
                title="Inspect Core Architectural Module",
                description="Examine inward dependency couplings and core shared domain logic.",
                citation=core_cit,
            )
        )

        if analysis_result.risk_signals:
            risk = analysis_result.risk_signals[0]
            tasks.append(
                StarterTask(
                    day=4,
                    title="Audit Highlighted Risk Signal",
                    description=f"Investigate risk area: {risk.description}.",
                    citation=f"{risk.citation.file_path}:{risk.citation.start_line}",
                )
            )
        else:
            tasks.append(
                StarterTask(
                    day=4,
                    title="Review Codebase Error Handling",
                    description=(
                        "Audit failure modes and validation rules across application boundaries."
                    ),
                    citation=core_cit,
                )
            )

        tasks.append(
            StarterTask(
                day=5,
                title="Implement Smoke Test or Utility",
                description=(
                    "Write an end-to-end unit test covering a leaf module to validate "
                    "development workflow."
                ),
                citation=test_cit,
            )
        )

        return tasks

    def _build_gotchas(self, analysis_result: AnalysisResult) -> list[GotchaItem]:
        gotchas: list[GotchaItem] = []
        for risk in analysis_result.risk_signals:
            gotchas.append(
                GotchaItem(
                    title=f"Risk in {risk.citation.file_path}",
                    risk_type=risk.signal_type,
                    explanation=risk.description,
                    citation=f"{risk.citation.file_path}:{risk.citation.start_line}",
                )
            )
        for circ in analysis_result.dependency_graph.circular_dependencies:
            cycle_str = " -> ".join(circ.cycle)
            cit = (
                f"{circ.citations[0].file_path}:{circ.citations[0].start_line}"
                if circ.citations
                else self.unclear
            )
            gotchas.append(
                GotchaItem(
                    title=f"Circular Import Cycle: {cycle_str}",
                    risk_type="Circular Dependency",
                    explanation=f"Cyclic import cycle detected across modules: {cycle_str}.",
                    citation=cit,
                )
            )
        return gotchas

    def _build_interactive_data(
        self, scan_result: ScanResult, analysis_result: AnalysisResult
    ) -> dict[str, Any]:
        files_data: list[dict[str, Any]] = []

        def traverse_node(node: Any) -> None:
            if not node.is_dir:
                files_data.append(
                    {
                        "path": node.path,
                        "lines": node.line_count,
                        "importance": node.importance_score,
                        "language": node.language,
                    }
                )
            for child in node.children:
                traverse_node(child)

        traverse_node(scan_result.file_tree)

        modules_data: list[dict[str, Any]] = []
        symbols_by_file: dict[str, list[str]] = {}
        for sym in analysis_result.symbols:
            symbols_by_file.setdefault(sym.citation.file_path, []).append(sym.name)

        for f in files_data:
            path = f["path"]
            syms = symbols_by_file.get(path, [])
            modules_data.append(
                {
                    "path": path,
                    "responsibility": f"Source module defining {len(syms)} primary code symbols.",
                    "symbols": syms[:10],
                    "citation": f"{path}:1",
                }
            )

        graph_nodes = [node.file_path for node in analysis_result.dependency_graph.nodes]
        graph_edges = [
            {"source": edge.source, "target": edge.target}
            for edge in analysis_result.dependency_graph.edges
        ]
        circular_nodes = [
            mod
            for circ in analysis_result.dependency_graph.circular_dependencies
            for mod in circ.cycle
        ]

        return {
            "files": files_data,
            "modules": modules_data,
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges,
                "circular": list(set(circular_nodes)),
            },
        }

    def generate(
        self,
        scan_result: ScanResult,
        analysis_result: AnalysisResult,
    ) -> dict[str, Path]:
        """Generate grounded ONBOARDING.md and interactive HTML dashboard."""
        purpose_text, purpose_cit = self._extract_purpose(scan_result)
        tech_stack = self._build_tech_stack(scan_result)

        top_arch = analysis_result.architecture[0] if analysis_result.architecture else None
        arch_name = top_arch.name if top_arch else "Monolith"
        arch_desc = (
            top_arch.description if top_arch else "Repository demonstrates monolithic architecture."
        )
        arch_cit = (
            f"{top_arch.citations[0].file_path}:{top_arch.citations[0].start_line}"
            if top_arch and top_arch.citations
            else self.unclear
        )

        all_modules = [n.file_path for n in analysis_result.dependency_graph.nodes]
        dep_tuples = [(e.source, e.target) for e in analysis_result.dependency_graph.edges]
        mermaid_diag = build_mermaid_architecture(arch_name, all_modules, dep_tuples)

        folder_guide = self._build_folder_guide(scan_result)
        feature_flows = self._build_feature_flows(scan_result, analysis_result)
        setup_steps = self._build_setup_steps(scan_result)
        glossary = self._build_glossary(analysis_result)
        conventions = [
            "Source files reside under distinct package directories.",
            "Test modules are collocated or organized in mirrored test directories.",
            "Configuration externalized via dedicated manifests.",
        ]
        starter_tasks = self._build_starter_tasks(scan_result, analysis_result)
        gotchas = self._build_gotchas(analysis_result)
        interactive_data = self._build_interactive_data(scan_result, analysis_result)

        raw_context = OnboardingContext(
            repo_name=scan_result.repo_name,
            purpose=purpose_text,
            purpose_citation=purpose_cit,
            tech_stack=tech_stack,
            architecture_name=arch_name,
            architecture_description=arch_desc,
            architecture_citation=arch_cit,
            mermaid_diagram=mermaid_diag,
            folder_guide=folder_guide,
            feature_flows=feature_flows,
            setup_steps=setup_steps,
            glossary=glossary,
            inferred_conventions=conventions,
            starter_tasks=starter_tasks,
            gotchas=gotchas,
            interactive_tree=interactive_data,
            interactive_modules=interactive_data["modules"],
            interactive_graph=interactive_data["graph"],
        )

        # Execute post-generation grounding pass across all claims and citations
        grounded_context = self.grounder.ground_context(raw_context)

        # Render ONBOARDING.md
        onboarding_path = Path(self.config.paths.onboarding_template)
        try:
            rel_onboarding = onboarding_path.relative_to(Path(self.config.paths.templates_dir))
            tmpl_name = str(rel_onboarding).replace("\\", "/")
        except ValueError:
            tmpl_name = f"output/{onboarding_path.name}"

        tmpl = self.jinja_env.get_template(tmpl_name)
        rendered_md = tmpl.render(grounded_context.model_dump())

        # Render index.html
        interactive_path = Path(self.config.paths.interactive_template)
        try:
            rel_interactive = interactive_path.relative_to(Path(self.config.paths.templates_dir))
            html_tmpl_name = str(rel_interactive).replace("\\", "/")
        except ValueError:
            html_tmpl_name = f"output/{interactive_path.name}"

        html_tmpl = self.jinja_env.get_template(html_tmpl_name)
        safe_json_data = safe_json_embed(interactive_data)
        rendered_html = html_tmpl.render(
            repo_name=grounded_context.repo_name,
            architecture_name=grounded_context.architecture_name,
            safe_json_data=safe_json_data,
        )

        # Write artifacts safely to output directory
        md_path = self.writer.write_artifact(self.config.ui.onboarding_md_filename, rendered_md)
        html_path = self.writer.write_artifact(
            self.config.ui.interactive_html_filename, rendered_html
        )

        return {
            "onboarding_md": md_path,
            "interactive_html": html_path,
        }
