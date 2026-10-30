"""Post-generation grounding pass verifying all citations against actual repository files."""

import logging
import re
from pathlib import Path

from codeguide.generator.models import OnboardingContext
from codeguide.llm.models import AnswerCitation, AskResponse, ExplainResponse

logger = logging.getLogger("codeguide.generator.grounding")

STOPWORDS = {
    "this",
    "that",
    "with",
    "from",
    "have",
    "been",
    "file",
    "code",
    "will",
    "line",
    "path",
    "user",
    "used",
    "each",
    "were",
    "when",
    "into",
    "more",
    "also",
    "then",
    "some",
    "such",
    "than",
    "must",
}


class CitationGrounder:
    """Verifies that cited files and lines exist and plausibly support the associated claims."""

    def __init__(self, repo_root: Path, unclear_marker: str = "unclear") -> None:
        self.repo_root = repo_root
        self.unclear_marker = unclear_marker
        self._file_cache: dict[str, list[str]] = {}

    def _read_file_lines(self, rel_path: str) -> list[str] | None:
        clean_path = rel_path.replace("\\", "/").strip().lstrip("/")
        if clean_path in self._file_cache:
            return self._file_cache[clean_path]

        target_file = self.repo_root / clean_path
        if not target_file.is_file():
            # Search for suffix match in repo if relative prefix differs
            matches = list(self.repo_root.rglob(Path(clean_path).name))
            if matches:
                target_file = matches[0]
            else:
                return None

        try:
            lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
            self._file_cache[clean_path] = lines
            return lines
        except Exception:
            return None

    def verify_citation(
        self,
        path: str,
        start_line: int,
        end_line: int,
        claim_text: str = "",
    ) -> tuple[bool, str]:
        if not path or path == self.unclear_marker:
            return False, self.unclear_marker

        lines = self._read_file_lines(path)
        if lines is None:
            return False, self.unclear_marker

        total_lines = len(lines)
        if start_line < 1 or end_line < start_line or end_line > max(total_lines, 1):
            return False, self.unclear_marker

        # Plausibility check: verify cited text has substantive relevance to the claim
        if claim_text and claim_text != self.unclear_marker:
            cited_snippet = " ".join(lines[start_line - 1 : end_line]).lower()
            tokens = re.findall(r"[a-zA-Z0-9_]{4,}", claim_text.lower())
            substantive_tokens = [t for t in tokens if t not in STOPWORDS]

            # If substantive tokens exist, at least one should appear in cited lines
            if substantive_tokens:
                if not any(token in cited_snippet for token in substantive_tokens):
                    logger.debug(
                        "Citation failed plausibility: tokens %s not in lines %d-%d of %s",
                        substantive_tokens[:3],
                        start_line,
                        end_line,
                        path,
                    )
                    return False, self.unclear_marker

        formatted = (
            f"{path}:{start_line}-{end_line}" if start_line != end_line else f"{path}:{start_line}"
        )
        return True, formatted

    def ground_citation_string(self, citation_str: str, claim_text: str = "") -> str:
        if not citation_str or citation_str == self.unclear_marker:
            return self.unclear_marker

        # Parse patterns like "path/file.py:10-25" or "path/file.py:10"
        m = re.match(r"^([^:]+):(\d+)(?:-(\d+))?$", citation_str.strip())
        if not m:
            # Check if citation_str is just a valid existing file path
            lines = self._read_file_lines(citation_str.strip())
            if lines is not None:
                return f"{citation_str.strip()}:1"
            return self.unclear_marker

        path = m.group(1).strip()
        start_line = int(m.group(2))
        end_line = int(m.group(3)) if m.group(3) else start_line

        valid, grounded = self.verify_citation(path, start_line, end_line, claim_text)
        return grounded if valid else self.unclear_marker

    def ground_context(self, context: OnboardingContext) -> OnboardingContext:
        ctx_data = context.model_dump()

        ctx_data["purpose_citation"] = self.ground_citation_string(
            ctx_data["purpose_citation"], ctx_data["purpose"]
        )
        ctx_data["architecture_citation"] = self.ground_citation_string(
            ctx_data["architecture_citation"], ctx_data["architecture_name"]
        )

        for item in ctx_data["tech_stack"]:
            item["citation"] = self.ground_citation_string(item["citation"], item["name"])

        for item in ctx_data["folder_guide"]:
            item["citation"] = self.ground_citation_string(item["citation"], item["purpose"])

        for flow in ctx_data["feature_flows"]:
            for step in flow["steps"]:
                step["citation"] = self.ground_citation_string(
                    step["citation"], step["description"]
                )

        for step in ctx_data["setup_steps"]:
            step["citation"] = self.ground_citation_string(step["citation"], step["instruction"])

        for term in ctx_data["glossary"]:
            term["citation"] = self.ground_citation_string(term["citation"], term["term"])

        for task in ctx_data["starter_tasks"]:
            task["citation"] = self.ground_citation_string(task["citation"], task["title"])

        for gotcha in ctx_data["gotchas"]:
            gotcha["citation"] = self.ground_citation_string(gotcha["citation"], gotcha["title"])

        return OnboardingContext.model_validate(ctx_data)

    def ground_ask_response(self, response: AskResponse) -> AskResponse:
        """Verify citations in ask response; revert to unclear if evidence is missing or invalid."""
        if not response.evidence_found:
            return AskResponse(
                answer=self.unclear_marker,
                evidence_found=False,
                citations=[],
                follow_up_questions=response.follow_up_questions,
            )

        valid_citations: list[AnswerCitation] = []
        for cit in response.citations:
            valid, _ = self.verify_citation(cit.path, cit.start_line, cit.end_line, response.answer)
            if valid:
                valid_citations.append(cit)

        if not valid_citations:
            return AskResponse(
                answer=self.unclear_marker,
                evidence_found=False,
                citations=[],
                follow_up_questions=response.follow_up_questions,
            )

        return AskResponse(
            answer=response.answer,
            evidence_found=True,
            citations=valid_citations,
            follow_up_questions=response.follow_up_questions,
        )

    def ground_explain_response(self, response: ExplainResponse) -> ExplainResponse:
        """Verify citations in explain response; revert to unclear if target has no evidence."""
        if not response.evidence_found:
            return ExplainResponse(
                target=response.target,
                audience_level=response.audience_level,
                summary=self.unclear_marker,
                explanation=self.unclear_marker,
                evidence_found=False,
                citations=[],
                follow_up_questions=response.follow_up_questions,
            )

        valid_citations: list[AnswerCitation] = []
        claim_context = f"{response.summary} {response.explanation}"
        for cit in response.citations:
            valid, _ = self.verify_citation(cit.path, cit.start_line, cit.end_line, claim_context)
            if valid:
                valid_citations.append(cit)

        if not valid_citations:
            return ExplainResponse(
                target=response.target,
                audience_level=response.audience_level,
                summary=self.unclear_marker,
                explanation=self.unclear_marker,
                evidence_found=False,
                citations=[],
                follow_up_questions=response.follow_up_questions,
            )

        return ExplainResponse(
            target=response.target,
            audience_level=response.audience_level,
            summary=response.summary,
            explanation=response.explanation,
            evidence_found=True,
            citations=valid_citations,
            follow_up_questions=response.follow_up_questions,
        )
