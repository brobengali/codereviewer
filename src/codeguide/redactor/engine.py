"""Standalone secret detection, entropy scoring, and redaction engine."""

import fnmatch
import importlib.resources
import math
import re
import tomllib
from pathlib import Path
from typing import Any

from codeguide.config.models import AppConfig
from codeguide.redactor.models import RedactedFinding, RedactionResult
from codeguide.scanner.models import (
    Citation,
    DetectedItem,
    DetectedSymbol,
    KeyDocument,
    ScanResult,
)


class SecretRedactor:
    """Detects credentials, keys, connection strings, and high-entropy strings and redacts them."""

    def __init__(self, config: AppConfig, rules: list[dict[str, Any]]) -> None:
        self.config = config
        self.rules = rules

    @classmethod
    def load(
        cls,
        config: AppConfig,
        custom_rules: list[dict[str, Any]] | None = None,
    ) -> "SecretRedactor":
        """Instantiate redactor from configuration and rule data files."""
        collected_rules: list[dict[str, Any]] = []

        # 1. Attempt to load bundled secret rules
        try:
            bundled = importlib.resources.files("codeguide").joinpath(
                "data", "rules", "secret_rules.toml"
            )
            with bundled.open("rb") as f:
                data = tomllib.load(f)
                collected_rules.extend(data.get("rules", []))
        except (TypeError, FileNotFoundError):
            pass

        # 2. Attempt to load from custom path if configured and distinct
        custom_file = Path(config.paths.secret_rules_file)
        if custom_file.is_file():
            with custom_file.open("rb") as f:
                data = tomllib.load(f)
                custom_rule_list = data.get("rules", [])
                existing_ids = {r["id"] for r in collected_rules}
                for r in custom_rule_list:
                    if r["id"] not in existing_ids:
                        collected_rules.append(r)

        # 3. Add explicit runtime rules if passed
        if custom_rules:
            collected_rules.extend(custom_rules)

        return cls(config=config, rules=collected_rules)

    def is_denied_file(self, file_path: str | Path) -> bool:
        """Return True if path matches any denied pattern (.env, .pem, .key, etc.)."""
        path_obj = Path(file_path)
        filename = path_obj.name
        posix_path = path_obj.as_posix()

        for pattern in self.config.security.denied_file_patterns:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(posix_path, pattern):
                return True
        return False

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy for a given token string."""
        if not data:
            return 0.0

        length = len(data)
        frequencies = {char: data.count(char) for char in set(data)}
        entropy = 0.0

        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def redact_text(self, text: str) -> RedactionResult:
        """Sanitize text by replacing regex matches and high-entropy tokens with placeholders."""
        if not text:
            return RedactionResult(clean_text=text, findings=[])

        findings: list[RedactedFinding] = []
        clean = text

        # 1. Regex rule redactions (structured formats, tokens, URLs, private keys)
        for rule in self.rules:
            pattern = rule["regex"]
            placeholder = rule["placeholder"]
            rule_id = rule["id"]
            capture_idx = rule.get("capture_group")

            try:
                compiled = re.compile(pattern)
            except re.error:
                continue

            matches = list(compiled.finditer(clean))
            # Process in reverse to maintain string index integrity
            for m in reversed(matches):
                if capture_idx is not None and len(m.groups()) >= capture_idx:
                    start = m.start(capture_idx)
                    end = m.end(capture_idx)
                    raw_val = m.group(capture_idx)
                else:
                    start = m.start()
                    end = m.end()
                    raw_val = m.group(0)

                if not raw_val:
                    continue

                line_no = clean.count("\n", 0, start) + 1
                preview = (
                    raw_val[:3] + ("*" * min(len(raw_val) - 3, 8)) if len(raw_val) > 3 else "***"
                )

                findings.append(
                    RedactedFinding(
                        rule_id=rule_id,
                        placeholder=placeholder,
                        line_number=line_no,
                        masked_preview=preview,
                    )
                )
                clean = clean[:start] + placeholder + clean[end:]

        # 2. High-entropy token detection (unstructured secrets, randomized base64/hex)
        min_len = self.config.security.min_entropy_length
        max_len = self.config.security.max_entropy_length
        threshold = self.config.security.entropy_threshold
        entropy_placeholder = self.config.security.entropy_placeholder

        # Split on common separators: whitespace, quotes, colons, equals, commas
        token_pat = r"([A-Za-z0-9+/=_\-]{" + str(min_len) + r"," + str(max_len) + r"})"
        token_pattern = re.compile(token_pat)
        entropy_matches = list(token_pattern.finditer(clean))

        for em in reversed(entropy_matches):
            token = em.group(1)
            # Skip tokens that are already placeholders or contain only one repeated character
            if token.startswith("[REDACTED:") or len(set(token)) <= 3:
                continue

            ent = self.calculate_entropy(token)
            if ent >= threshold:
                start = em.start(1)
                end = em.end(1)
                line_no = clean.count("\n", 0, start) + 1
                preview = token[:3] + ("*" * min(len(token) - 3, 8))

                findings.append(
                    RedactedFinding(
                        rule_id="high_entropy",
                        placeholder=entropy_placeholder,
                        line_number=line_no,
                        masked_preview=preview,
                    )
                )
                clean = clean[:start] + entropy_placeholder + clean[end:]

        findings.reverse()
        return RedactionResult(clean_text=clean, findings=findings)

    def redact_scan_result(
        self,
        scan_result: ScanResult,
    ) -> tuple[ScanResult, list[RedactedFinding]]:
        """Deeply sanitize all snippets, document bodies, and metadata within a ScanResult."""
        all_findings: list[RedactedFinding] = []

        # 1. Sanitize raw documents
        sanitized_docs: list[KeyDocument] = []
        for doc in scan_result.documents:
            res = self.redact_text(doc.content)
            all_findings.extend(res.findings)
            sanitized_docs.append(
                KeyDocument(
                    path=doc.path,
                    category=doc.category,
                    content=res.clean_text,
                    line_count=doc.line_count,
                )
            )

        # 2. Sanitize entry points
        sanitized_entry_points: list[DetectedSymbol] = []
        for ep in scan_result.entry_points:
            cit_res = self.redact_text(ep.citation.snippet)
            all_findings.extend(cit_res.findings)
            sanitized_entry_points.append(
                DetectedSymbol(
                    name=ep.name,
                    kind=ep.kind,
                    details=ep.details,
                    citation=Citation(
                        file_path=ep.citation.file_path,
                        start_line=ep.citation.start_line,
                        end_line=ep.citation.end_line,
                        snippet=cit_res.clean_text,
                    ),
                )
            )

        # 3. Sanitize routes
        sanitized_routes: list[DetectedSymbol] = []
        for rt in scan_result.routes:
            cit_res = self.redact_text(rt.citation.snippet)
            all_findings.extend(cit_res.findings)
            sanitized_routes.append(
                DetectedSymbol(
                    name=rt.name,
                    kind=rt.kind,
                    details=rt.details,
                    citation=Citation(
                        file_path=rt.citation.file_path,
                        start_line=rt.citation.start_line,
                        end_line=rt.citation.end_line,
                        snippet=cit_res.clean_text,
                    ),
                )
            )

        # 4. Sanitize DB models
        sanitized_models: list[DetectedSymbol] = []
        for md in scan_result.db_models:
            cit_res = self.redact_text(md.citation.snippet)
            all_findings.extend(cit_res.findings)
            sanitized_models.append(
                DetectedSymbol(
                    name=md.name,
                    kind=md.kind,
                    details=md.details,
                    citation=Citation(
                        file_path=md.citation.file_path,
                        start_line=md.citation.start_line,
                        end_line=md.citation.end_line,
                        snippet=cit_res.clean_text,
                    ),
                )
            )

        # 5. Sanitize env vars
        sanitized_env_vars: list[DetectedSymbol] = []
        for ev in scan_result.env_vars:
            cit_res = self.redact_text(ev.citation.snippet)
            all_findings.extend(cit_res.findings)
            sanitized_env_vars.append(
                DetectedSymbol(
                    name=ev.name,
                    kind=ev.kind,
                    details=ev.details,
                    citation=Citation(
                        file_path=ev.citation.file_path,
                        start_line=ev.citation.start_line,
                        end_line=ev.citation.end_line,
                        snippet=cit_res.clean_text,
                    ),
                )
            )

        # 6. Sanitize framework / tool evidence snippets
        sanitized_frameworks: list[DetectedItem] = []
        for fw in scan_result.frameworks:
            clean_evidence: list[Citation] = []
            for fw_ev in fw.evidence:
                c_res = self.redact_text(fw_ev.snippet)
                all_findings.extend(c_res.findings)
                clean_evidence.append(
                    Citation(
                        file_path=fw_ev.file_path,
                        start_line=fw_ev.start_line,
                        end_line=fw_ev.end_line,
                        snippet=c_res.clean_text,
                    )
                )
            sanitized_frameworks.append(
                DetectedItem(
                    name=fw.name,
                    category=fw.category,
                    confidence=fw.confidence,
                    evidence=clean_evidence,
                )
            )

        sanitized_pms: list[DetectedItem] = []
        for pm in scan_result.package_managers:
            pm_evidence: list[Citation] = []
            for pm_ev in pm.evidence:
                c_res = self.redact_text(pm_ev.snippet)
                all_findings.extend(c_res.findings)
                pm_evidence.append(
                    Citation(
                        file_path=pm_ev.file_path,
                        start_line=pm_ev.start_line,
                        end_line=pm_ev.end_line,
                        snippet=c_res.clean_text,
                    )
                )
            sanitized_pms.append(
                DetectedItem(
                    name=pm.name,
                    category=pm.category,
                    confidence=pm.confidence,
                    evidence=pm_evidence,
                )
            )

        sanitized_tts: list[DetectedItem] = []
        for tt in scan_result.test_tools:
            tt_evidence: list[Citation] = []
            for tt_ev in tt.evidence:
                c_res = self.redact_text(tt_ev.snippet)
                all_findings.extend(c_res.findings)
                tt_evidence.append(
                    Citation(
                        file_path=tt_ev.file_path,
                        start_line=tt_ev.start_line,
                        end_line=tt_ev.end_line,
                        snippet=c_res.clean_text,
                    )
                )
            sanitized_tts.append(
                DetectedItem(
                    name=tt.name,
                    category=tt.category,
                    confidence=tt.confidence,
                    evidence=tt_evidence,
                )
            )

        sanitized_result = ScanResult(
            repo_name=scan_result.repo_name,
            repo_path=scan_result.repo_path,
            total_files=scan_result.total_files,
            total_lines=scan_result.total_lines,
            total_size_bytes=scan_result.total_size_bytes,
            languages=scan_result.languages,
            frameworks=sanitized_frameworks,
            package_managers=sanitized_pms,
            test_tools=sanitized_tts,
            entry_points=sanitized_entry_points,
            routes=sanitized_routes,
            db_models=sanitized_models,
            env_vars=sanitized_env_vars,
            file_tree=scan_result.file_tree,
            documents=sanitized_docs,
        )

        return sanitized_result, all_findings
