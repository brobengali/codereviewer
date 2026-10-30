"""Prompt synthesis with random data boundaries and anti-slop rules."""

import secrets
import tomllib
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from codeguide.config.models import AppConfig


class PromptManager:
    """Manages Jinja prompt compilation and data boundary isolation."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.prompts_dir = Path(config.paths.prompts_dir)
        if not self.prompts_dir.is_dir():
            self.prompts_dir = (
                Path(__file__).resolve().parent.parent.parent.parent / "templates" / "prompts"
            )

        # Plain text prompt templates do not use HTML autoescape
        self.jinja_env = Environment(  # nosec B701
            loader=FileSystemLoader(str(self.prompts_dir)),
            autoescape=False,  # noqa: S701
        )
        self.style_rules: dict[str, Any] = {}
        self._load_style_rules()

    def _load_style_rules(self) -> None:
        p = Path(self.config.paths.style_rules_file)
        if not p.is_file():
            p = Path(__file__).resolve().parent.parent / "data" / "style_rules.toml"
        if p.is_file():
            with p.open("rb") as f:
                self.style_rules = tomllib.load(f)

    def generate_boundary_token(self) -> str:
        return secrets.token_hex(16)

    def render_system_prompt(self, boundary_token: str) -> str:
        template = self.jinja_env.get_template("system.jinja2")
        ctx = {
            "boundary_token": boundary_token,
            "max_sentence_length": self.config.style.max_sentence_length,
            "banned_phrases": self.config.style.banned_phrases,
            "banned_openers": self.config.style.banned_openers,
            "vague_words": self.config.style.vague_words,
        }
        return template.render(**ctx)

    def render_user_prompt(
        self,
        template_name: str,
        boundary_token: str,
        context: dict[str, Any],
    ) -> str:
        template = self.jinja_env.get_template(template_name)
        ctx = dict(context)
        ctx["boundary_token"] = boundary_token
        return template.render(**ctx)
