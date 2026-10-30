"""Data-driven architectural pattern detection."""

import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from codeguide.analyzer.models import ArchitectureFinding
from codeguide.config.models import AppConfig
from codeguide.scanner.models import Citation


class ArchitectureDetector:
    """Evaluates repository structure against external architectural pattern rules."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        p = Path(self.config.paths.architecture_rules_file)
        if not p.is_file():
            p = Path(__file__).resolve().parent.parent / "data" / "architecture_rules.toml"
        if p.is_file():
            with p.open("rb") as f:
                data = tomllib.load(f)
                self.rules = data.get("patterns", [])

    def detect(self, known_files: list[str]) -> list[ArchitectureFinding]:
        # Extract unique directories and base file names
        dir_set: set[str] = set()
        file_base_set: set[str] = set()

        for f in known_files:
            posix = PurePosixPath(f)
            file_base_set.add(posix.name.lower())
            for part in posix.parts[:-1]:
                dir_set.add(part.lower())

        findings: list[ArchitectureFinding] = []

        for rule in self.rules:
            pattern_id = rule.get("id", "")
            name = rule.get("name", "")
            indicators = [ind.lower() for ind in rule.get("indicators", [])]
            exclusions = [exc.lower() for exc in rule.get("exclusion_indicators", [])]
            match_type = rule.get("match_type", "directory_presence")
            min_matched = rule.get("min_matched", 1)
            threshold = float(rule.get("confidence_threshold", 0.7))
            desc = rule.get("description", "")

            # If exclusion indicators are present, skip this pattern
            if any(exc in dir_set or exc in file_base_set for exc in exclusions):
                continue

            matched_evidence: list[str] = []

            if match_type == "directory_presence":
                for ind in indicators:
                    if ind in dir_set:
                        matched_evidence.append(ind)
            elif match_type in ("any_presence", "directory_and_manifest"):
                for ind in indicators:
                    if ind in dir_set or ind in file_base_set:
                        matched_evidence.append(ind)
            elif match_type == "monolith_heuristic":
                # Single cohesive application root without monorepo/microservice indicators
                for ind in indicators:
                    if ind in dir_set:
                        matched_evidence.append(ind)

            if len(matched_evidence) >= min_matched:
                if match_type in ("any_presence", "directory_and_manifest", "monolith_heuristic"):
                    confidence = round(min(1.0, 0.75 + (len(matched_evidence) * 0.10)), 2)
                else:
                    total_expected = max(len(indicators), 1)
                    confidence = round(min(1.0, (len(matched_evidence) / total_expected) + 0.35), 2)

                if confidence >= threshold:
                    citations = [
                        Citation(
                            file_path=ev,
                            start_line=1,
                            end_line=1,
                            snippet=f"Matched architectural indicator: {ev}",
                        )
                        for ev in matched_evidence
                    ]
                    findings.append(
                        ArchitectureFinding(
                            pattern_id=pattern_id,
                            name=name,
                            confidence=confidence,
                            description=desc,
                            evidence_paths=matched_evidence,
                            citations=citations,
                        )
                    )

        # Sort findings by descending confidence
        findings.sort(key=lambda x: x.confidence, reverse=True)
        return findings
