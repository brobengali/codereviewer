"""Google GenAI SDK provider implementation with zero tools and structured output."""

import json
import logging
from typing import Any

import google.genai as genai
from google.genai import types
from pydantic import BaseModel

from codeguide.common.messages import msg
from codeguide.config.models import LLMConfig
from codeguide.llm.base import LLMProvider
from codeguide.llm.key import SecretKey

logger = logging.getLogger("codeguide.llm.gemini")


class GoogleGenAIProvider(LLMProvider):
    """Google GenAI SDK provider enforcing JSON schema outputs without tools."""

    def __init__(self, config: LLMConfig, secret_key: SecretKey) -> None:
        self.config = config
        self.secret_key = secret_key
        raw_key = secret_key.get_secret_value() if secret_key else ""

        http_opts = types.HttpOptions(
            base_url=config.api_base_url if config.api_base_url else None,
            timeout=int(config.request_timeout_seconds * 1000),
        )
        self.client = genai.Client(api_key=raw_key, http_options=http_opts)

    def build_generation_config(
        self,
        schema: type[BaseModel],
        system_instruction: str | None = None,
    ) -> types.GenerateContentConfig:
        safety_list = [
            types.SafetySetting(
                category=types.HarmCategory(s.category),
                threshold=types.HarmBlockThreshold(s.threshold),
            )
            for s in self.config.safety_settings
        ]
        thinking = (
            types.ThinkingConfig(thinking_budget=self.config.thinking_budget)
            if self.config.thinking_budget > 0
            else None
        )

        # Explicitly enforce NO tools, NO grounding, NO code execution
        cfg = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=self.config.temperature,
            max_output_tokens=self.config.max_output_tokens,
            response_mime_type="application/json",
            response_schema=schema,
            thinking_config=thinking,
            safety_settings=safety_list,
            tools=None,
            tool_config=None,
            automatic_function_calling=None,
        )

        if cfg.tools is not None or cfg.tool_config is not None:
            raise RuntimeError("Tools must not be configured for LLM requests")
        return cfg

    def generate(
        self,
        prompt: str,
        schema: type[BaseModel],
        system_instruction: str | None = None,
    ) -> dict[str, Any]:
        gen_cfg = self.build_generation_config(schema, system_instruction)
        response = self.client.models.generate_content(
            model=self.config.model_name,
            contents=prompt,
            config=gen_cfg,
        )

        # Guard against blocked or empty responses
        if response.candidates:
            first_candidate = response.candidates[0]
            finish_reason = getattr(first_candidate, "finish_reason", None)
            if finish_reason not in (None, "STOP", types.FinishReason.STOP):
                reason_str = str(finish_reason)
                raise RuntimeError(msg("errors.llm_safety_blocked", reason=reason_str))

        raw_text = response.text
        if not raw_text or not raw_text.strip():
            raise RuntimeError(msg("errors.llm_safety_blocked", reason="Empty content returned"))

        # Local validation with pydantic
        try:
            parsed_json = json.loads(raw_text)
            validated = schema.model_validate(parsed_json)
            return validated.model_dump()
        except Exception as exc:
            err_msg = msg("errors.llm_schema_invalid", errors=str(exc))
            raise ValueError(err_msg) from exc


GeminiProvider = GoogleGenAIProvider
