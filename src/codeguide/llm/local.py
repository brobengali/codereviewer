"""OpenAI-compatible local server provider for Ollama and llama.cpp."""

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from pydantic import BaseModel

from codeguide.common.messages import msg
from codeguide.config.models import LLMConfig
from codeguide.llm.base import LLMProvider
from codeguide.llm.key import SecretKey

logger = logging.getLogger("codeguide.llm.local")


class LocalProvider(LLMProvider):
    """Interacts with OpenAI-compatible local API endpoints."""

    def __init__(self, config: LLMConfig, secret_key: SecretKey | None = None) -> None:
        self.config = config
        self.secret_key = secret_key

    def generate(
        self,
        prompt: str,
        schema: type[BaseModel],
        system_instruction: str | None = None,
    ) -> dict[str, Any]:
        base = self.config.api_base_url.rstrip("/")
        endpoint = f"{base}/v1/chat/completions" if not base.endswith("/chat/completions") else base

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        schema_json = schema.model_json_schema()
        body = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_output_tokens,
            "response_format": {"type": "json_object", "schema": schema_json},
        }

        data_bytes = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret_key:
            headers["Authorization"] = f"Bearer {self.secret_key.get_secret_value()}"

        req = urllib.request.Request(  # noqa: S310
            endpoint, data=data_bytes, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(  # nosec B310 # noqa: S310
                req, timeout=float(self.config.request_timeout_seconds)
            ) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                msg("errors.llm_request_failed", retries=0, reason=str(exc))
            ) from exc

        choices = res_data.get("choices", [])
        if not choices:
            raise RuntimeError(msg("errors.llm_safety_blocked", reason="Empty choices returned"))

        message = choices[0].get("message", {})
        raw_text = message.get("content", "")
        if not raw_text or not raw_text.strip():
            raise RuntimeError(msg("errors.llm_safety_blocked", reason="Empty message content"))

        try:
            parsed = json.loads(raw_text)
            validated = schema.model_validate(parsed)
            return validated.model_dump()
        except Exception as exc:
            err_msg = msg("errors.llm_schema_invalid", errors=str(exc))
            raise ValueError(err_msg) from exc
