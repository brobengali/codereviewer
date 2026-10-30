"""Rule engine driving repository detection entirely from external data files."""

import importlib.resources
import re
import tomllib
from pathlib import Path
from typing import Any

from codeguide.config.models import AppConfig
from codeguide.scanner.models import Citation, DetectedItem, DetectedSymbol


class RuleEngine:
    """Loads and evaluates external TOML detection rules for languages, frameworks, and patterns."""

    def __init__(self) -> None:
        self.languages: list[dict[str, Any]] = []
        self.frameworks: list[dict[str, Any]] = []
        self.package_managers: list[dict[str, Any]] = []
        self.test_tools: list[dict[str, Any]] = []
        self.entry_point_rules: list[dict[str, Any]] = []
        self.route_rules: list[dict[str, Any]] = []
        self.db_model_rules: list[dict[str, Any]] = []
        self.env_var_rules: list[dict[str, Any]] = []

    @classmethod
    def load(cls, config: AppConfig, extra_rules: list[Path] | None = None) -> "RuleEngine":
        """Instantiate engine by discovering bundled and custom rule files."""
        engine = cls()

        # Discover rules from package data directory
        try:
            bundled = importlib.resources.files("codeguide").joinpath("data", "rules")
            for item in bundled.iterdir():
                if item.name.endswith(".toml"):
                    with item.open("rb") as f:
                        engine.merge_rule_dict(tomllib.load(f))
        except (TypeError, FileNotFoundError):
            pass

        # Load from configured custom rules directory if present on filesystem
        custom_dir = Path(config.paths.rules_dir)
        if custom_dir.is_dir():
            for rule_file in custom_dir.glob("*.toml"):
                with rule_file.open("rb") as f:
                    engine.merge_rule_dict(tomllib.load(f))

        # Merge explicitly passed rule files
        if extra_rules:
            for extra in extra_rules:
                if extra.is_file():
                    with extra.open("rb") as f:
                        engine.merge_rule_dict(tomllib.load(f))

        return engine

    def merge_rule_dict(self, data: dict[str, Any]) -> None:
        """Merge rule specifications from a parsed data file."""
        if "languages" in data:
            self.languages.extend(data["languages"])
        if "frameworks" in data:
            self.frameworks.extend(data["frameworks"])
        if "package_managers" in data:
            self.package_managers.extend(data["package_managers"])
        if "test_tools" in data:
            self.test_tools.extend(data["test_tools"])
        if "entry_points" in data:
            self.entry_point_rules.extend(data["entry_points"])
        if "routes" in data:
            self.route_rules.extend(data["routes"])
        if "db_models" in data:
            self.db_model_rules.extend(data["db_models"])
        if "env_vars" in data:
            self.env_var_rules.extend(data["env_vars"])

    def detect_language(self, filename: str, first_line: str = "") -> str | None:
        """Detect language from extension, exact filename, or shebang line."""
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""

        for lang in self.languages:
            if ext and ext in [e.lower() for e in lang.get("extensions", [])]:
                return lang["name"]
            if filename in lang.get("filenames", []):
                return lang["name"]
            if first_line.startswith("#!"):
                for shebang in lang.get("shebangs", []):
                    if shebang in first_line:
                        return lang["name"]
        return None

    def match_package_managers(
        self,
        discovered_files: list[str],
        file_contents: dict[str, str],
    ) -> list[DetectedItem]:
        """Identify package managers by indicator files or manifest substrings."""
        detected: list[DetectedItem] = []
        discovered_set = set(discovered_files)

        for pm in self.package_managers:
            matched = False
            evidence: list[Citation] = []

            for indicator in pm.get("file_indicators", []):
                if indicator in discovered_set:
                    matched = True
                    evidence.append(
                        Citation(
                            file_path=indicator,
                            start_line=1,
                            end_line=1,
                            snippet=f"Found package manager indicator file: {indicator}",
                        )
                    )
                    break

            if not matched:
                for check in pm.get("manifest_patterns", []):
                    m_file = check["file"]
                    m_pat = check["pattern"]
                    if m_file in file_contents and m_pat in file_contents[m_file]:
                        matched = True
                        evidence.append(
                            Citation(
                                file_path=m_file,
                                start_line=1,
                                end_line=1,
                                snippet=f"Matched pattern '{m_pat}' in manifest",
                            )
                        )
                        break

            if matched:
                detected.append(
                    DetectedItem(
                        name=pm["name"],
                        category="package_manager",
                        confidence=1.0,
                        evidence=evidence,
                    )
                )
        return detected

    def match_frameworks(
        self,
        discovered_files: list[str],
        file_contents: dict[str, str],
    ) -> list[DetectedItem]:
        """Detect web or application frameworks from manifest dependencies and imports."""
        detected: list[DetectedItem] = []

        for fw in self.frameworks:
            evidence: list[Citation] = []

            # 1. Check manifests
            for manifest_file in fw.get("manifest_files", []):
                for path, content in file_contents.items():
                    if path.endswith(manifest_file):
                        for pattern in fw.get("manifest_patterns", []):
                            if pattern.lower() in content.lower():
                                evidence.append(
                                    Citation(
                                        file_path=path,
                                        start_line=1,
                                        end_line=1,
                                        snippet=f"Matched manifest dependency: {pattern}",
                                    )
                                )
                                break

            # 2. Check source code import indicators if manifest match wasn't found
            if not evidence:
                for path, content in file_contents.items():
                    for code_pat in fw.get("code_patterns", []):
                        if code_pat in content:
                            evidence.append(
                                Citation(
                                    file_path=path,
                                    start_line=1,
                                    end_line=1,
                                    snippet=f"Matched code import: {code_pat}",
                                )
                            )
                            break
                    if evidence:
                        break

            if evidence:
                detected.append(
                    DetectedItem(
                        name=fw["name"],
                        category=fw.get("category", "framework"),
                        confidence=0.9,
                        evidence=evidence,
                    )
                )

        return detected

    def match_test_tools(
        self,
        discovered_files: list[str],
        file_contents: dict[str, str],
    ) -> list[DetectedItem]:
        """Detect test runners and frameworks."""
        detected: list[DetectedItem] = []
        discovered_set = set(discovered_files)

        for tt in self.test_tools:
            evidence: list[Citation] = []
            for indicator in tt.get("file_indicators", []):
                if "*" in indicator:
                    matches = [f for f in discovered_files if Path(f).match(indicator)]
                    if matches:
                        evidence.append(
                            Citation(
                                file_path=matches[0],
                                start_line=1,
                                end_line=1,
                                snippet=f"Found test file: {matches[0]}",
                            )
                        )
                        break
                elif indicator in discovered_set:
                    evidence.append(
                        Citation(
                            file_path=indicator,
                            start_line=1,
                            end_line=1,
                            snippet=f"Found test configuration file: {indicator}",
                        )
                    )
                    break

            if not evidence:
                for check in tt.get("manifest_patterns", []):
                    m_file = check["file"]
                    m_pat = check["pattern"]
                    for path, content in file_contents.items():
                        if path.endswith(m_file) and m_pat in content:
                            evidence.append(
                                Citation(
                                    file_path=path,
                                    start_line=1,
                                    end_line=1,
                                    snippet=f"Found test dependency '{m_pat}' in {path}",
                                )
                            )
                            break

            if not evidence:
                for path, content in file_contents.items():
                    for code_pat in tt.get("code_patterns", []):
                        if code_pat in content:
                            evidence.append(
                                Citation(
                                    file_path=path,
                                    start_line=1,
                                    end_line=1,
                                    snippet=f"Found test pattern: {code_pat}",
                                )
                            )
                            break
                    if evidence:
                        break

            if evidence:
                detected.append(
                    DetectedItem(
                        name=tt["name"],
                        category="test_tool",
                        confidence=0.9,
                        evidence=evidence,
                    )
                )

        return detected

    def extract_symbols(
        self,
        file_path: str,
        lines: list[str],
    ) -> tuple[
        list[DetectedSymbol],
        list[DetectedSymbol],
        list[DetectedSymbol],
        list[DetectedSymbol],
    ]:
        """Extract entry points, routes, DB models, and env vars with citations."""
        entry_points: list[DetectedSymbol] = []
        routes: list[DetectedSymbol] = []
        db_models: list[DetectedSymbol] = []
        env_vars: list[DetectedSymbol] = []

        filename = Path(file_path).name

        # 1. Entry points
        for ep in self.entry_point_rules:
            if "filename" in ep and filename == ep["filename"]:
                entry_points.append(
                    DetectedSymbol(
                        name=ep["capture_name"],
                        kind="entry_point",
                        details={"rule_id": ep["id"]},
                        citation=Citation(
                            file_path=file_path,
                            start_line=1,
                            end_line=1,
                            snippet=lines[0] if lines else "",
                        ),
                    )
                )
            elif "filename_patterns" in ep and filename in ep["filename_patterns"]:
                entry_points.append(
                    DetectedSymbol(
                        name=ep["capture_name"],
                        kind="entry_point",
                        details={"rule_id": ep["id"]},
                        citation=Citation(
                            file_path=file_path,
                            start_line=1,
                            end_line=1,
                            snippet=lines[0] if lines else "",
                        ),
                    )
                )
            elif "regex" in ep:
                compiled = re.compile(ep["regex"])
                for idx, line in enumerate(lines, start=1):
                    if compiled.search(line):
                        entry_points.append(
                            DetectedSymbol(
                                name=ep["capture_name"],
                                kind="entry_point",
                                details={"rule_id": ep["id"]},
                                citation=Citation(
                                    file_path=file_path,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=line.strip(),
                                ),
                            )
                        )
                        break

        # 2. Routes and Env vars (line by line)
        for idx, line in enumerate(lines, start=1):
            # Routes
            for r_rule in self.route_rules:
                match = re.search(r_rule["regex"], line)
                if match:
                    groups = match.groups()
                    method = (
                        groups[r_rule["method_group"] - 1].upper()
                        if "method_group" in r_rule and len(groups) >= r_rule["method_group"]
                        else "ANY"
                    )
                    path = (
                        groups[r_rule["path_group"] - 1]
                        if "path_group" in r_rule and len(groups) >= r_rule["path_group"]
                        else "/"
                    )
                    routes.append(
                        DetectedSymbol(
                            name=f"{method} {path}",
                            kind="route",
                            details={"method": method, "path": path, "rule_id": r_rule["id"]},
                            citation=Citation(
                                file_path=file_path,
                                start_line=idx,
                                end_line=idx,
                                snippet=line.strip(),
                            ),
                        )
                    )

            # Env vars
            for ev_rule in self.env_var_rules:
                match = re.search(ev_rule["regex"], line)
                if match:
                    groups = match.groups()
                    idx_grp = ev_rule.get("var_name_group", 1) - 1
                    has_group = len(groups) > idx_grp and groups[idx_grp]
                    var_name = groups[idx_grp] if has_group else None
                    if not var_name and "fallback_var_name_group" in ev_rule:
                        fallback_idx = ev_rule["fallback_var_name_group"] - 1
                        if len(groups) > fallback_idx:
                            var_name = groups[fallback_idx]

                    if var_name:
                        env_vars.append(
                            DetectedSymbol(
                                name=var_name,
                                kind="env_var",
                                details={"rule_id": ev_rule["id"]},
                                citation=Citation(
                                    file_path=file_path,
                                    start_line=idx,
                                    end_line=idx,
                                    snippet=line.strip(),
                                ),
                            )
                        )

        # 3. DB Models (evaluated against multiline source to accommodate class decorators)
        full_text = "\n".join(lines)
        for m_rule in self.db_model_rules:
            for match in re.finditer(m_rule["regex"], full_text):
                groups = match.groups()
                idx_grp = m_rule["model_name_group"] - 1
                model_name = groups[idx_grp] if len(groups) > idx_grp else "Model"
                match_pos = (
                    match.start(m_rule["model_name_group"])
                    if len(groups) > idx_grp
                    else match.start()
                )
                line_idx = full_text.count("\n", 0, match_pos) + 1
                snippet = lines[line_idx - 1].strip() if line_idx <= len(lines) else ""
                db_models.append(
                    DetectedSymbol(
                        name=model_name,
                        kind="db_model",
                        details={"rule_id": m_rule["id"]},
                        citation=Citation(
                            file_path=file_path,
                            start_line=line_idx,
                            end_line=line_idx,
                            snippet=snippet,
                        ),
                    )
                )

        return entry_points, routes, db_models, env_vars
