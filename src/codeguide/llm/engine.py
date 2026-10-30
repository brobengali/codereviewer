"""High-level LLM orchestration engine managing providers, caching, and validation."""

import json
import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from codeguide.common.messages import msg
from codeguide.config.models import AppConfig
from codeguide.llm.base import LLMProvider
from codeguide.llm.cache import LLMCache
from codeguide.llm.gemini import GeminiProvider
from codeguide.llm.key import KeyMaskingFilter, SecretKey, resolve_api_key
from codeguide.llm.local import LocalProvider
from codeguide.llm.models import ExplanationResponse, LLMRequestPayload, LLMResponse
from codeguide.llm.prompts import PromptManager
from codeguide.llm.rate_limiter import RateLimiter, retry_with_backoff

logger = logging.getLogger("codeguide.llm")


class LLMEngine:
    """Executes structured LLM calls with caching, retry logic, and citation verification."""

    def __init__(
        self,
        config: AppConfig,
        provider: LLMProvider | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.config = config
        self.prompt_manager = PromptManager(config)
        self.cache = LLMCache(config.llm)
        self.secret_key: SecretKey | None = None

        if provider is not None:
            self.provider = provider
        else:
            self._init_key_and_provider()

        if rate_limiter is not None:
            self.rate_limiter = rate_limiter
        else:
            self.rate_limiter = RateLimiter(
                requests_per_minute=config.llm.requests_per_minute,
                tokens_per_minute=config.llm.tokens_per_minute,
            )

    def _init_key_and_provider(self) -> None:
        # Check offline mode constraint
        if self.config.llm.offline:
            if self.config.llm.provider != "local":
                raise ValueError(
                    msg("errors.offline_provider_disallowed", provider=self.config.llm.provider)
                )
            self.provider = LocalProvider(self.config.llm)
            return

        # Online mode: resolve secret key
        self.secret_key = resolve_api_key(self.config.llm)
        if not self.secret_key:
            raise ValueError(
                msg(
                    "errors.missing_api_key",
                    env_var=self.config.llm.api_key_env_var,
                    service=self.config.llm.keyring_service_name,
                )
            )

        # Attach masking filter to logger
        key_filter = KeyMaskingFilter(self.secret_key.get_secret_value())
        logger.addFilter(key_filter)

        if self.config.llm.provider == "local":
            self.provider = LocalProvider(self.config.llm, self.secret_key)
        else:
            self.provider = GeminiProvider(self.config.llm, self.secret_key)

    def validate_citations(
        self,
        data: dict[str, Any],
        context_file_ranges: dict[str, int],
    ) -> list[str]:
        errors: list[str] = []
        normalized_ranges = {
            k.replace("\\", "/").lower(): v for k, v in context_file_ranges.items()
        }

        # Check claims-based schema
        claims = data.get("claims", [])
        if claims:
            for idx, claim in enumerate(claims):
                citations = claim.get("citations", [])
                if not citations:
                    errors.append(f"Claim {idx} has empty citations list")
                    continue
                for cit in citations:
                    errors.extend(self._validate_single_citation(cit, normalized_ranges))
            return errors

        # Check direct citations schema (e.g. AskResponse / ExplainResponse)
        evidence_found = data.get("evidence_found", True)
        citations = data.get("citations", [])
        if evidence_found and not citations:
            answer_text = str(data.get("answer") or data.get("explanation") or "").lower()
            if self.config.style.unclear_marker not in answer_text:
                errors.append("Evidence claimed but citations list is empty")
        for cit in citations:
            errors.extend(self._validate_single_citation(cit, normalized_ranges))

        return errors

    def _validate_single_citation(
        self,
        cit: dict[str, Any],
        normalized_ranges: dict[str, int],
    ) -> list[str]:
        errors: list[str] = []
        path = cit.get("path", "").replace("\\", "/").lower()
        start_l = cit.get("start_line", 0)
        end_l = cit.get("end_line", 0)

        matched_max = None
        for k, max_l in normalized_ranges.items():
            if k.endswith(path) or path.endswith(k):
                matched_max = max_l
                break

        if matched_max is None:
            errors.append(f"Citation path '{cit.get('path')}' not found in context")
        elif start_l < 1 or end_l < start_l or end_l > matched_max:
            cit_path = cit.get("path")
            errors.append(
                f"Citation {cit_path}:{start_l}-{end_l} out of line range (1-{matched_max})"
            )
        return errors

    def generate(
        self,
        template_name: str,
        template_context: dict[str, Any],
        schema: type[BaseModel] = ExplanationResponse,
        context_file_ranges: dict[str, int] | None = None,
        dry_run: bool = False,
    ) -> LLMResponse:
        ranges = context_file_ranges or {}
        boundary_token = self.prompt_manager.generate_boundary_token()
        system_prompt = self.prompt_manager.render_system_prompt(boundary_token)
        user_prompt = self.prompt_manager.render_user_prompt(
            template_name, boundary_token, template_context
        )

        # Handle dry-run mode
        if dry_run:
            payload = LLMRequestPayload(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=self.config.llm.model_name,
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_output_tokens,
                schema_definition=schema.model_json_schema(),
                boundary_token=boundary_token,
            )
            return LLMResponse(success=True, data=payload.model_dump())

        # Compute canonical content for caching independent of per-request random boundary token
        canonical_content = (
            f"{template_name}:{json.dumps(template_context, sort_keys=True, default=str)}"
        )
        cache_key = self.cache.compute_key(
            redacted_content=canonical_content,
            template_version="1.0.0",
            model_name=self.config.llm.model_name,
            schema_version="1.0.0",
        )
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return LLMResponse(success=True, data=cached_result, cached=True)

        def call_provider(prompt_text: str) -> dict[str, Any]:
            self.rate_limiter.acquire(estimated_tokens=len(prompt_text.split()))
            return self.provider.generate(
                prompt=prompt_text,
                schema=schema,
                system_instruction=system_prompt,
            )

        # First generation attempt with retry
        try:
            result_dict = retry_with_backoff(
                lambda: call_provider(user_prompt),
                max_retries=self.config.llm.max_retries,
                backoff_factor=self.config.llm.backoff_factor,
            )
        except Exception as exc:
            return LLMResponse(success=False, error=str(exc))

        # Citation validation
        citation_errors = self.validate_citations(result_dict, ranges)
        if citation_errors:
            # Retry ONCE with validation errors appended as data
            retry_prompt = (
                f"{user_prompt}\n\n"
                f"VALIDATION ERROR ENCOUNTERED:\n"
                f"{'; '.join(citation_errors)}\n"
                f"Please regenerate output correcting the citation errors."
            )
            try:
                result_dict = call_provider(retry_prompt)
                second_errors = self.validate_citations(result_dict, ranges)
                if second_errors:
                    return LLMResponse(
                        success=False,
                        error=f"Citation validation failed on retry: {'; '.join(second_errors)}",
                    )
            except (ValueError, ValidationError, Exception) as exc:
                return LLMResponse(success=False, error=str(exc))

        # Cache validated output
        self.cache.set(cache_key, canonical_content, result_dict)
        return LLMResponse(success=True, data=result_dict)
