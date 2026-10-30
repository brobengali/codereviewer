"""Documentation slop linter checking style rules, citations, specificity, and repetition."""

import difflib
import re
import tomllib
from pathlib import Path

from codeguide.common.messages import msg
from codeguide.config.models import AppConfig
from codeguide.slop.models import DocLintResult, SlopViolation

CITATION_REGEX = re.compile(r"(?:^|[\s\(\[`])([a-zA-Z0-9_\-\./]+\.[a-zA-Z0-9]+):(\d+)(?:-(\d+))?")
BACKTICK_REGEX = re.compile(r"`([^`]+)`")
NUMBER_REGEX = re.compile(r"\b\d+(?:\.\d+)*\b")
BULLET_PREFIX_REGEX = re.compile(r"^\s*(?:[-*+]|\d+\.)\s*")


class DocSlopChecker:
    """Audits documentation files for banned phrases, missing citations, slop, and repetition."""

    def __init__(self, config: AppConfig, repo_path: Path | None = None) -> None:
        self.config = config
        self.repo_path = repo_path.resolve() if repo_path and repo_path.exists() else None
        self._load_rules()
        self._build_repo_vocabulary()

    def _load_rules(self) -> None:
        self.banned_phrases: list[str] = list(self.config.style.banned_phrases)
        self.banned_openers: list[str] = list(self.config.style.banned_openers)
        self.vague_words: list[str] = list(self.config.style.vague_words)
        self.max_sentence_length: int = self.config.slop.max_sentence_length
        self.unclear_marker: str = self.config.style.unclear_marker.lower()
        self.repetition_threshold: float = self.config.slop.repetition_similarity_threshold

        # Augment with external style_rules.toml if available
        rules_file = Path(self.config.paths.style_rules_file)
        if rules_file.is_file():
            try:
                with rules_file.open("rb") as f:
                    data = tomllib.load(f)
                    if "banned_phrases" in data and "phrases" in data["banned_phrases"]:
                        self.banned_phrases.extend(data["banned_phrases"]["phrases"])
                    if "banned_openers" in data and "openers" in data["banned_openers"]:
                        self.banned_openers.extend(data["banned_openers"]["openers"])
                    if "vague_words" in data and "words" in data["vague_words"]:
                        self.vague_words.extend(data["vague_words"]["words"])
            except (OSError, tomllib.TOMLDecodeError):
                pass

        # Deduplicate case-insensitively while preserving lowercase values
        self.banned_phrases = list({p.strip().lower() for p in self.banned_phrases if p.strip()})
        self.banned_openers = list({o.strip().lower() for o in self.banned_openers if o.strip()})
        self.vague_words = list({w.strip().lower() for w in self.vague_words if w.strip()})

    def _build_repo_vocabulary(self) -> None:
        self.repo_filenames: set[str] = set()
        self.repo_identifiers: set[str] = set()
        self.repo_commands: set[str] = {
            "python",
            "pytest",
            "ruff",
            "mypy",
            "bandit",
            "pip-audit",
            "codeguide",
            "git",
            "pip",
            "docker",
        }

        if not self.repo_path:
            return

        for p in self.repo_path.rglob("*"):
            if any(part.startswith(".") for part in p.parts):
                continue
            if p.is_file():
                self.repo_filenames.add(p.name.lower())
                self.repo_filenames.add(p.stem.lower())
                # Extract potential identifiers from short code files
                if p.suffix in (".py", ".toml", ".json", ".yaml", ".yml"):
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        words = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", text)
                        for w in words[:1000]:
                            self.repo_identifiers.add(w.lower())
                    except OSError:
                        continue

    def lint_file(self, file_path: Path) -> DocLintResult:
        if not file_path.is_file():
            raise FileNotFoundError(msg("errors.doc_file_not_found", path=str(file_path)))
        text = file_path.read_text(encoding="utf-8")
        return self.lint_text(text, filename=str(file_path))

    def lint_text(self, text: str, filename: str = "document.md") -> DocLintResult:
        lines = text.splitlines()
        violations: list[SlopViolation] = []
        in_code_fence = False
        total_sentences = 0
        seen_statements: list[tuple[str, int]] = []

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Handle markdown code fences
            if stripped.startswith("```"):
                in_code_fence = not in_code_fence
                continue
            if in_code_fence:
                continue

            # Skip empty lines, horizontal rules, table rows, and comments
            if (
                not stripped
                or stripped.startswith("|")
                or stripped.startswith("<!--")
                or re.match(r"^[-*_]{3,}$", stripped)
            ):
                continue

            is_heading = stripped.startswith("#")
            clean_line = BULLET_PREFIX_REGEX.sub("", stripped)

            # Split line into sentences
            raw_sentences = self._split_sentences(clean_line)
            for sentence in raw_sentences:
                s_clean = sentence.strip()
                if not s_clean:
                    continue

                total_sentences += 1
                s_lower = s_clean.lower()

                # 1. Banned openers check
                for opener in self.banned_openers:
                    if s_lower.startswith(opener):
                        violations.append(
                            SlopViolation(
                                category="banned_opener",
                                file_path=filename,
                                line_number=line_idx,
                                message=msg(
                                    "errors.banned_opener_detected", opener=opener, line=line_idx
                                ),
                                snippet=s_clean,
                                severity=1.0,
                            )
                        )
                        break

                # 2. Banned phrases check
                for phrase in self.banned_phrases:
                    # Match phrase on word boundaries
                    pat = r"\b" + re.escape(phrase) + r"\b"
                    if re.search(pat, s_lower):
                        violations.append(
                            SlopViolation(
                                category="banned_phrase",
                                file_path=filename,
                                line_number=line_idx,
                                message=msg(
                                    "errors.banned_phrase_detected", phrase=phrase, line=line_idx
                                ),
                                snippet=s_clean,
                                severity=1.0,
                            )
                        )
                        break

                # Headings are exempt from citation and specificity checks
                if is_heading:
                    continue

                # 3. Missing citation or unclear marker check
                citations = self._extract_citations(s_clean)
                has_unclear = self.unclear_marker in s_lower
                if not citations and not has_unclear:
                    violations.append(
                        SlopViolation(
                            category="missing_citation",
                            file_path=filename,
                            line_number=line_idx,
                            message=msg(
                                "errors.missing_citation_detected", line=line_idx, snippet=s_clean
                            ),
                            snippet=s_clean,
                            severity=1.0,
                        )
                    )

                # 4. Citation validity check (nonexistent file or out-of-range line)
                if self.repo_path and citations:
                    for cited_file, start_line, end_line in citations:
                        target = (self.repo_path / cited_file).resolve()
                        if not target.is_file():
                            violations.append(
                                SlopViolation(
                                    category="invalid_citation",
                                    file_path=filename,
                                    line_number=line_idx,
                                    message=msg(
                                        "errors.invalid_citation_target",
                                        path=cited_file,
                                        line=line_idx,
                                    ),
                                    snippet=s_clean,
                                    severity=1.0,
                                )
                            )
                        else:
                            try:
                                count = len(
                                    target.read_text(encoding="utf-8", errors="ignore").splitlines()
                                )
                                checked_line = end_line if end_line is not None else start_line
                                if checked_line > count:
                                    violations.append(
                                        SlopViolation(
                                            category="invalid_citation",
                                            file_path=filename,
                                            line_number=line_idx,
                                            message=msg(
                                                "errors.citation_out_of_range",
                                                cited_line=checked_line,
                                                path=cited_file,
                                                max_line=count,
                                                line=line_idx,
                                            ),
                                            snippet=s_clean,
                                            severity=1.0,
                                        )
                                    )
                            except OSError:
                                pass

                # 5. Generic sentence specificity check
                specificity_score = self._compute_specificity(s_clean, citations)
                if specificity_score < self.config.slop.min_specificity_score:
                    violations.append(
                        SlopViolation(
                            category="low_specificity",
                            file_path=filename,
                            line_number=line_idx,
                            message=msg(
                                "errors.low_specificity_detected",
                                score=specificity_score,
                                line=line_idx,
                                snippet=s_clean,
                            ),
                            snippet=s_clean,
                            severity=1.0,
                        )
                    )

                # 6. Repetition check (near-duplicate statements)
                norm_statement = self._normalize_statement(s_clean)
                if len(norm_statement.split()) >= 3:
                    for prior_text, prior_line in seen_statements:
                        ratio = difflib.SequenceMatcher(None, norm_statement, prior_text).ratio()
                        if ratio >= self.repetition_threshold:
                            violations.append(
                                SlopViolation(
                                    category="repetition",
                                    file_path=filename,
                                    line_number=line_idx,
                                    message=msg(
                                        "errors.repetition_detected",
                                        line=line_idx,
                                        similarity=ratio,
                                        prior_line=prior_line,
                                        snippet=s_clean,
                                    ),
                                    snippet=s_clean,
                                    severity=1.0,
                                )
                            )
                            break
                    seen_statements.append((norm_statement, line_idx))

                # 7. Sentence length check
                words = s_clean.split()
                if len(words) > self.max_sentence_length:
                    violations.append(
                        SlopViolation(
                            category="sentence_length",
                            file_path=filename,
                            line_number=line_idx,
                            message=msg(
                                "errors.sentence_too_long",
                                count=len(words),
                                limit=self.max_sentence_length,
                                line=line_idx,
                            ),
                            snippet=s_clean,
                            severity=1.0,
                        )
                    )

        slop_score = float(len(violations))
        passed = slop_score <= self.config.slop.max_slop_score

        return DocLintResult(
            file_path=filename,
            violations=violations,
            total_sentences=total_sentences,
            slop_score=slop_score,
            passed=passed,
        )

    def _split_sentences(self, text: str) -> list[str]:
        # Split on sentence boundaries (. ! ?) while keeping inline abbreviations intact
        sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`\"'\[])", text)
        return [s.strip() for s in sentences if s.strip()]

    def _extract_citations(self, text: str) -> list[tuple[str, int, int | None]]:
        results: list[tuple[str, int, int | None]] = []
        for match in CITATION_REGEX.finditer(text):
            path_str = match.group(1)
            start_l = int(match.group(2))
            end_l = int(match.group(3)) if match.group(3) else None
            results.append((path_str, start_l, end_l))
        return results

    def _compute_specificity(
        self, sentence: str, citations: list[tuple[str, int, int | None]]
    ) -> float:
        points = 0.0

        # An explicit 'unclear' marker satisfies falsifiability for missing evidence
        if self.unclear_marker in sentence.lower():
            points += 1.0

        # Backticked code tokens or citation paths contribute high specificity
        backticks = BACKTICK_REGEX.findall(sentence)
        points += float(len(backticks))
        points += float(len(citations))

        # Explicit numeric constants / versions contribute specificity
        numbers = NUMBER_REGEX.findall(sentence)
        points += float(len(numbers))

        # Token match against repo files, identifiers, or CLI commands
        words = re.findall(r"\b[A-Za-z_][A-Za-z0-9_\-\.]*\b", sentence.lower())
        for w in words:
            if w in self.repo_filenames:
                points += 1.0
            elif w in self.repo_identifiers:
                points += 0.5
            elif w in self.repo_commands:
                points += 0.5

        return points

    def _normalize_statement(self, text: str) -> str:
        # Strip citations and backticks to compare purely semantic textual content
        clean = CITATION_REGEX.sub("", text)
        clean = BACKTICK_REGEX.sub(r"\1", clean)
        clean = re.sub(r"[^\w\s]", "", clean.lower())
        return " ".join(clean.split())
