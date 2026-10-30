"""Repository health and maintenance risk signal detection."""

import fnmatch
from pathlib import PurePosixPath

from codeguide.analyzer.models import ParsedFile, RiskSignal
from codeguide.config.models import AppConfig
from codeguide.scanner.models import Citation


class RiskAnalyzer:
    """Evaluates files and parse results for maintenance and reliability risks."""

    def __init__(self, config: AppConfig, known_files: list[str]) -> None:
        self.config = config
        self.known_files = known_files
        self.known_filenames_lower = {PurePosixPath(f).name.lower() for f in known_files}

    def analyze_file(
        self,
        parsed_file: ParsedFile,
        raw_lines: list[str],
    ) -> list[RiskSignal]:
        risks: list[RiskSignal] = []
        cfg = self.config.analysis.risk_signals
        file_path = parsed_file.file_path
        lines_count = parsed_file.lines_count

        # 1. Huge file check
        if lines_count > cfg.huge_file_lines_threshold:
            desc = f"File exceeds {cfg.huge_file_lines_threshold} lines ({lines_count} lines)"
            risks.append(
                RiskSignal(
                    signal_type="huge_file",
                    severity="medium",
                    description=desc,
                    citation=Citation(
                        file_path=file_path, start_line=1, end_line=lines_count, snippet=desc
                    ),
                )
            )

        # 2. Parse failure check
        if parsed_file.has_errors:
            err_line = parsed_file.error_line or 1
            desc = "Syntax parse error detected during AST evaluation"
            risks.append(
                RiskSignal(
                    signal_type="parse_failure",
                    severity="warning",
                    description=desc,
                    citation=Citation(
                        file_path=file_path, start_line=err_line, end_line=err_line, snippet=desc
                    ),
                )
            )

        # 3. TODO/FIXME clusters
        todo_lines: list[int] = []
        for idx, line in enumerate(raw_lines, start=1):
            if any(pat in line for pat in cfg.todo_patterns):
                todo_lines.append(idx)

        if len(todo_lines) >= cfg.todo_cluster_threshold:
            # Check if clustered within the configured window
            is_clustered = (todo_lines[-1] - todo_lines[0]) <= cfg.todo_cluster_window_lines or len(
                todo_lines
            ) >= 5
            if is_clustered:
                desc = f"Cluster of {len(todo_lines)} TODO/FIXME markers discovered"
                snippet_text = "\n".join(raw_lines[todo_lines[0] - 1 : todo_lines[-1]])[:200]
                risks.append(
                    RiskSignal(
                        signal_type="todo_cluster",
                        severity="low",
                        description=desc,
                        citation=Citation(
                            file_path=file_path,
                            start_line=todo_lines[0],
                            end_line=todo_lines[-1],
                            snippet=snippet_text,
                        ),
                    )
                )

        # 4. Untested file check
        posix = PurePosixPath(file_path)
        ext = posix.suffix.lower()
        if ext in cfg.source_file_extensions:
            is_test_itself = (
                any(
                    fnmatch.fnmatch(posix.name.lower(), pat.lower())
                    for pat in cfg.test_file_patterns
                )
                or "test" in posix.parts
            )
            if not is_test_itself:
                stem = posix.stem.lower()
                has_test = False
                for pat in cfg.test_file_patterns:
                    expected_test_name = pat.replace("*", stem).lower()
                    if expected_test_name in self.known_filenames_lower:
                        has_test = True
                        break
                if not has_test:
                    desc = "Source module lacks corresponding test file"
                    risks.append(
                        RiskSignal(
                            signal_type="untested_file",
                            severity="low",
                            description=desc,
                            citation=Citation(
                                file_path=file_path, start_line=1, end_line=1, snippet=desc
                            ),
                        )
                    )

        return risks
