"""CodeGuide command line interface."""

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from codeguide import __version__
from codeguide.analyzer.engine import RepositoryAnalyzer
from codeguide.common.messages import msg
from codeguide.common.redaction import mask_sensitive_dict
from codeguide.config.loader import load_config
from codeguide.generator.engine import DocumentationGenerator
from codeguide.generator.grounding import CitationGrounder
from codeguide.llm.engine import LLMEngine
from codeguide.llm.local import LocalProvider
from codeguide.llm.models import AskResponse, ExplainResponse
from codeguide.redactor.engine import SecretRedactor
from codeguide.repo.loader import SecureRepoContext
from codeguide.retrieval.engine import RetrievalEngine
from codeguide.scanner.scanner import RepositoryScanner
from codeguide.slop.code_checker import CodeSlopChecker
from codeguide.slop.doc_checker import DocSlopChecker

app = typer.Typer(
    name="codeguide",
    help=msg("cli.app_help"),
    no_args_is_help=True,
)

config_app = typer.Typer(
    name="config",
    help=msg("cli.config_app_help"),
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


@app.command()
def version() -> None:
    """Print version information."""
    config = load_config()
    typer.echo(msg("cli.version_output", version=__version__, schema_version=config.meta.version))


@config_app.command(name="show")
def show_config(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to custom config file."),
    ] = None,
) -> None:
    """Print active configuration hierarchy with secrets masked."""
    cfg = load_config(config_path=config_file)
    dumped = cfg.model_dump()
    masked = mask_sensitive_dict(
        dumped,
        sensitive_keys=cfg.security.sensitive_key_names,
        mask_value=cfg.security.mask_value,
    )
    typer.echo(json.dumps(masked, indent=2))


@config_app.command(name="validate")
def validate_config(
    config_file: Annotated[
        Path,
        typer.Argument(help="Path to configuration file to validate."),
    ],
) -> None:
    """Validate a specific codeguide.toml file against the schema."""
    try:
        cfg = load_config(config_path=config_file)
        typer.echo(msg("cli.config_valid", path=config_file, schema_version=cfg.meta.version))
    except Exception as exc:
        err_msg = msg("cli.config_invalid", error=str(exc))
        typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def analyze(
    repo_target: Annotated[
        str | None,
        typer.Argument(help="Path to local code repository or remote Git URL."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to custom codeguide.toml file."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", "-m", help="LLM model identifier override."),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="Directory where generated output is saved."),
    ] = None,
    verbose: Annotated[
        bool | None,
        typer.Option("--verbose", "-v", help="Enable verbose diagnostic logs."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show sanitized payload prepared for external output."),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Operate strictly offline using local provider."),
    ] = False,
) -> None:
    """Analyze repository entrypoint and architecture (CLI skeleton)."""
    cli_overrides: dict[str, Any] = {}
    if model is not None:
        cli_overrides.setdefault("llm", {})["model_name"] = model
    if output_dir is not None:
        cli_overrides.setdefault("paths", {})["output_dir"] = str(output_dir)
    if verbose is not None:
        cli_overrides.setdefault("ui", {})["verbose"] = verbose
    if offline:
        cli_overrides.setdefault("llm", {})["offline"] = True

    cfg = load_config(config_path=config_file, cli_overrides=cli_overrides)
    target = repo_target if repo_target is not None else "."

    try:
        with SecureRepoContext(target, cfg) as repo_root:
            scanner = RepositoryScanner(repo_root, cfg)
            raw_scan = scanner.scan()
            redactor = SecretRedactor.load(cfg)
            sanitized_scan, _ = redactor.redact_scan_result(raw_scan)

            analyzer = RepositoryAnalyzer(cfg)
            analysis_res = analyzer.analyze(repo_root, sanitized_scan)

            if dry_run:
                payload = sanitized_scan.model_dump()
                payload["analysis"] = analysis_res.model_dump()
                llm_engine = LLMEngine(cfg, provider=LocalProvider(cfg.llm))
                llm_dry_run = llm_engine.generate(
                    template_name="repo_overview.jinja2",
                    template_context={
                        "repo_name": sanitized_scan.repo_name,
                        "architecture_name": (
                            analysis_res.architecture[0].name
                            if analysis_res.architecture
                            else "unclear"
                        ),
                        "core_modules": analysis_res.dependency_graph.core_modules,
                        "documents": [d.model_dump() for d in sanitized_scan.documents],
                    },
                    dry_run=True,
                )
                payload["llm_request"] = llm_dry_run.data
                typer.echo(json.dumps(payload, indent=2))
                return

            typer.echo(msg("cli.target_repo_info", path=repo_root))
            typer.echo(msg("logging.scan_complete", files_count=raw_scan.total_files))
            if analysis_res.architecture:
                top_arch = analysis_res.architecture[0]
                typer.echo(
                    msg(
                        "cli.architecture_detected",
                        architecture=top_arch.name,
                        confidence=top_arch.confidence,
                    )
                )
            typer.echo(
                msg(
                    "cli.analysis_summary",
                    symbols_count=len(analysis_res.symbols),
                    edges_count=len(analysis_res.dependency_graph.edges),
                    risks_count=len(analysis_res.risk_signals),
                )
            )
            typer.echo(msg("cli.configured_model_info", model=cfg.llm.model_name))
            typer.echo(msg("cli.output_dir_info", path=cfg.paths.output_dir))

            generator = DocumentationGenerator(cfg, repo_root)
            artifacts = generator.generate(sanitized_scan, analysis_res)
            typer.echo(
                msg(
                    "cli.generation_complete",
                    onboarding=artifacts["onboarding_md"].name,
                    interactive=artifacts["interactive_html"].name,
                )
            )
    except (FileNotFoundError, PermissionError, ValueError, TimeoutError, RuntimeError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def ask(
    question: Annotated[
        str,
        typer.Argument(help="Question to answer about repository code."),
    ],
    repo_target: Annotated[
        str | None,
        typer.Option("--repo", "-r", help="Path to local repository or remote Git URL."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to custom codeguide.toml file."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", "-m", help="LLM model identifier override."),
    ] = None,
    retrieval_mode: Annotated[
        str | None,
        typer.Option("--retrieval", help="Retrieval mode: keyword or embeddings."),
    ] = None,
    top_k: Annotated[
        int | None,
        typer.Option(
            "--top-k", "-k", help="Number of retrieved code chunks to include in context."
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Operate strictly offline using local provider."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show prepared prompt payload without executing LLM."),
    ] = False,
) -> None:
    """Answer technical questions about the repository backed by exact citations."""
    cli_overrides: dict[str, Any] = {}
    if model is not None:
        cli_overrides.setdefault("llm", {})["model_name"] = model
    if retrieval_mode is not None:
        cli_overrides.setdefault("retrieval", {})["mode"] = retrieval_mode
    if top_k is not None:
        cli_overrides.setdefault("retrieval", {})["top_k"] = top_k
    if offline:
        cli_overrides.setdefault("llm", {})["offline"] = True

    cfg = load_config(config_path=config_file, cli_overrides=cli_overrides)
    target = repo_target if repo_target is not None else "."

    try:
        with SecureRepoContext(target, cfg) as repo_root:
            scanner = RepositoryScanner(repo_root, cfg)
            raw_scan = scanner.scan()
            redactor = SecretRedactor.load(cfg)
            sanitized_scan, _ = redactor.redact_scan_result(raw_scan)

            analyzer = RepositoryAnalyzer(cfg)
            analysis_res = analyzer.analyze(repo_root, sanitized_scan)

            retrieval_engine = RetrievalEngine(cfg)
            retrieval_engine.index_repository(repo_root, sanitized_scan, analysis_res)
            results = retrieval_engine.search(question, top_k=cfg.retrieval.top_k)

            retrieved_chunks = [
                {
                    "path": r.chunk.file_path,
                    "start_line": r.chunk.start_line,
                    "end_line": r.chunk.end_line,
                    "content": r.chunk.content,
                }
                for r in results
            ]
            context_file_ranges = {r.chunk.file_path: r.chunk.end_line for r in results}

            tmpl_path = Path(cfg.paths.ask_template).name
            llm_provider = LocalProvider(cfg.llm) if (offline or dry_run) else None
            llm_engine = LLMEngine(cfg, provider=llm_provider)

            if dry_run:
                dry_run_resp = llm_engine.generate(
                    template_name=tmpl_path,
                    template_context={
                        "question": question,
                        "retrieved_chunks": retrieved_chunks,
                    },
                    schema=AskResponse,
                    context_file_ranges=context_file_ranges,
                    dry_run=True,
                )
                typer.echo(json.dumps(dry_run_resp.data, indent=2))
                return

            llm_resp = llm_engine.generate(
                template_name=tmpl_path,
                template_context={
                    "question": question,
                    "retrieved_chunks": retrieved_chunks,
                },
                schema=AskResponse,
                context_file_ranges=context_file_ranges,
            )

            if not llm_resp.success or not llm_resp.data:
                raise RuntimeError(llm_resp.error or "LLM generation failed.")

            raw_answer = AskResponse.model_validate(llm_resp.data)
            grounder = CitationGrounder(repo_root, unclear_marker=cfg.style.unclear_marker)
            grounded_answer = grounder.ground_ask_response(raw_answer)

            typer.echo(msg("cli.ask_header", question=question))
            typer.echo(f"\n{msg('cli.answer_heading')} {grounded_answer.answer}\n")

            if grounded_answer.citations:
                typer.echo(msg("cli.citations_heading"))
                for cit in grounded_answer.citations:
                    line_span = (
                        f"{cit.start_line}-{cit.end_line}"
                        if cit.start_line != cit.end_line
                        else f"{cit.start_line}"
                    )
                    typer.echo(f"  - {cit.path}:{line_span}")
                typer.echo("")

            if grounded_answer.follow_up_questions:
                typer.echo(msg("cli.followups_heading"))
                for fq in grounded_answer.follow_up_questions:
                    typer.echo(f"  - {fq}")
    except (
        FileNotFoundError,
        PermissionError,
        ValueError,
        TimeoutError,
        RuntimeError,
    ) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def explain(
    target: Annotated[
        str,
        typer.Argument(help="File path or symbol name to explain."),
    ],
    repo_target: Annotated[
        str | None,
        typer.Option("--repo", "-r", help="Path to local repository or remote Git URL."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to custom codeguide.toml file."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", "-m", help="LLM model identifier override."),
    ] = None,
    audience: Annotated[
        str | None,
        typer.Option("--audience", "-a", help="Audience level: junior, mid, or senior."),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Operate strictly offline using local provider."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show prepared prompt payload without executing LLM."),
    ] = False,
) -> None:
    """Explain a file or symbol adapted to audience level with grounding citations."""
    cli_overrides: dict[str, Any] = {}
    if model is not None:
        cli_overrides.setdefault("llm", {})["model_name"] = model
    if offline:
        cli_overrides.setdefault("llm", {})["offline"] = True

    cfg = load_config(config_path=config_file, cli_overrides=cli_overrides)
    aud_level = audience or cfg.ui.default_audience_level
    if aud_level not in cfg.ui.supported_audience_levels:
        err = msg(
            "errors.unsupported_audience",
            audience=aud_level,
            allowed=", ".join(cfg.ui.supported_audience_levels),
        )
        typer.secho(err, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    repo_path = repo_target if repo_target is not None else "."

    try:
        with SecureRepoContext(repo_path, cfg) as repo_root:
            scanner = RepositoryScanner(repo_root, cfg)
            raw_scan = scanner.scan()
            redactor = SecretRedactor.load(cfg)
            sanitized_scan, _ = redactor.redact_scan_result(raw_scan)

            analyzer = RepositoryAnalyzer(cfg)
            analysis_res = analyzer.analyze(repo_root, sanitized_scan)

            retrieval_engine = RetrievalEngine(cfg)
            retrieval_engine.index_repository(repo_root, sanitized_scan, analysis_res)
            results = retrieval_engine.search_target(target, top_k=cfg.retrieval.top_k)

            retrieved_chunks = [
                {
                    "path": r.chunk.file_path,
                    "start_line": r.chunk.start_line,
                    "end_line": r.chunk.end_line,
                    "content": r.chunk.content,
                }
                for r in results
            ]
            context_file_ranges = {r.chunk.file_path: r.chunk.end_line for r in results}

            tmpl_path = Path(cfg.paths.explain_template).name
            llm_provider = LocalProvider(cfg.llm) if (offline or dry_run) else None
            llm_engine = LLMEngine(cfg, provider=llm_provider)

            if dry_run:
                dry_run_resp = llm_engine.generate(
                    template_name=tmpl_path,
                    template_context={
                        "target": target,
                        "audience_level": aud_level,
                        "retrieved_chunks": retrieved_chunks,
                    },
                    schema=ExplainResponse,
                    context_file_ranges=context_file_ranges,
                    dry_run=True,
                )
                typer.echo(json.dumps(dry_run_resp.data, indent=2))
                return

            llm_resp = llm_engine.generate(
                template_name=tmpl_path,
                template_context={
                    "target": target,
                    "audience_level": aud_level,
                    "retrieved_chunks": retrieved_chunks,
                },
                schema=ExplainResponse,
                context_file_ranges=context_file_ranges,
            )

            if not llm_resp.success or not llm_resp.data:
                raise RuntimeError(llm_resp.error or "LLM generation failed.")

            raw_explain = ExplainResponse.model_validate(llm_resp.data)
            grounder = CitationGrounder(repo_root, unclear_marker=cfg.style.unclear_marker)
            grounded_explain = grounder.ground_explain_response(raw_explain)

            typer.echo(msg("cli.explain_header", target=target, audience=aud_level))
            typer.echo(f"\n{grounded_explain.summary}\n")
            typer.echo(f"{grounded_explain.explanation}\n")

            if grounded_explain.citations:
                typer.echo(msg("cli.citations_heading"))
                for cit in grounded_explain.citations:
                    line_span = (
                        f"{cit.start_line}-{cit.end_line}"
                        if cit.start_line != cit.end_line
                        else f"{cit.start_line}"
                    )
                    typer.echo(f"  - {cit.path}:{line_span}")
                typer.echo("")

            if grounded_explain.follow_up_questions:
                typer.echo(msg("cli.followups_heading"))
                for fq in grounded_explain.follow_up_questions:
                    typer.echo(f"  - {fq}")
    except (
        FileNotFoundError,
        PermissionError,
        ValueError,
        TimeoutError,
        RuntimeError,
    ) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command(name="lint-docs")
def lint_docs(
    doc_file: Annotated[
        Path,
        typer.Argument(help="Path to documentation file to audit for slop."),
    ],
    repo_path: Annotated[
        Path | None,
        typer.Option("--repo", "-r", help="Path to repository for citation grounding."),
    ] = None,
    threshold: Annotated[
        float | None,
        typer.Option("--threshold", "-t", help="Slop score threshold before failing."),
    ] = None,
) -> None:
    """Audit a documentation file for banned phrases, missing citations, slop, and repetition."""
    cfg = load_config()
    eff_threshold = threshold if threshold is not None else cfg.slop.max_slop_score
    checker = DocSlopChecker(cfg, repo_path=repo_path)

    try:
        res = checker.lint_file(doc_file)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(msg("cli.lint_docs_header", path=doc_file))
    for v in res.violations:
        typer.secho(f"  [{v.category}] Line {v.line_number}: {v.message}", fg=typer.colors.YELLOW)

    if res.slop_score > eff_threshold:
        err_msg = msg(
            "cli.lint_docs_failed",
            score=res.slop_score,
            threshold=eff_threshold,
            count=len(res.violations),
        )
        typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    clean_msg = msg("cli.lint_docs_clean", score=res.slop_score, threshold=eff_threshold)
    typer.secho(clean_msg, fg=typer.colors.GREEN)


@app.command(name="lint-code")
def lint_code(
    repo_path: Annotated[
        Path | None,
        typer.Argument(help="Path to repository to audit for code slop."),
    ] = None,
    threshold: Annotated[
        float | None,
        typer.Option("--threshold", "-t", help="Slop score threshold before failing."),
    ] = None,
) -> None:
    """Audit Python codebase for restating comments, dead functions, stubs, and slop."""
    cfg = load_config()
    target_dir = repo_path.resolve() if repo_path else Path.cwd()
    eff_threshold = threshold if threshold is not None else cfg.slop.max_slop_score
    checker = CodeSlopChecker(cfg, target_dir)
    res = checker.lint_repo()

    typer.echo(msg("cli.lint_code_header", path=target_dir))
    for v in res.violations:
        typer.secho(
            f"  [{v.category}] {v.file_path}:{v.line_number}: {v.message}",
            fg=typer.colors.YELLOW,
        )

    if res.slop_score > eff_threshold:
        err_msg = msg(
            "cli.lint_code_failed",
            score=res.slop_score,
            threshold=eff_threshold,
            count=len(res.violations),
        )
        typer.secho(err_msg, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    clean_msg = msg("cli.lint_code_clean", score=res.slop_score, threshold=eff_threshold)
    typer.secho(clean_msg, fg=typer.colors.GREEN)
