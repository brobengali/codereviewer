"""Slop checking and anti-slop verification modules for documentation and codebase."""

from codeguide.slop.code_checker import CodeSlopChecker
from codeguide.slop.doc_checker import DocSlopChecker
from codeguide.slop.models import CodeLintResult, DocLintResult, SlopViolation

__all__ = [
    "CodeLintResult",
    "CodeSlopChecker",
    "DocLintResult",
    "DocSlopChecker",
    "SlopViolation",
]
