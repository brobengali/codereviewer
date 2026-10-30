"""Client-side request and token rate limiting with jittered backoff retries."""

import logging
import random
import time
from collections import deque
from typing import Any, Callable

logger = logging.getLogger("codeguide.llm.rate_limiter")


class RateLimiter:
    """Sliding-window rate limiter governing requests and tokens per minute."""

    def __init__(
        self,
        requests_per_minute: int,
        tokens_per_minute: int,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.requests_per_minute = max(1, requests_per_minute)
        self.tokens_per_minute = max(1, tokens_per_minute)
        self.clock = clock
        self.sleeper = sleeper
        self._request_events: deque[float] = deque()
        self._token_events: deque[tuple[float, int]] = deque()
        self._window_seconds: float = 60.0

    def acquire(self, estimated_tokens: int = 1) -> None:
        while True:
            now = self.clock()
            self._prune(now)

            curr_tokens = sum(t[1] for t in self._token_events)
            is_req_capped = len(self._request_events) >= self.requests_per_minute
            is_tok_capped = (curr_tokens + estimated_tokens) > self.tokens_per_minute

            if not is_req_capped and not is_tok_capped:
                self._request_events.append(now)
                self._token_events.append((now, estimated_tokens))
                return

            # Determine necessary sleep time until oldest entry rolls out of window
            oldest_req = self._request_events[0] if self._request_events else now
            oldest_tok = self._token_events[0][0] if self._token_events else now
            oldest = min(oldest_req, oldest_tok)
            sleep_duration = max(0.01, (oldest + self._window_seconds) - now)
            self.sleeper(sleep_duration)

    def _prune(self, now: float) -> None:
        threshold = now - self._window_seconds
        while self._request_events and self._request_events[0] <= threshold:
            self._request_events.popleft()
        while self._token_events and self._token_events[0][0] <= threshold:
            self._token_events.popleft()


def is_retryable_error(exc: Exception) -> bool:
    """Determines if an API or network error qualifies for automatic retry."""
    # Never retry authentication, forbidden, or bad request client errors
    status_code = getattr(exc, "status_code", getattr(exc, "code", None))
    if status_code in (400, 401, 403, 404):
        return False

    name = exc.__class__.__name__
    if "Auth" in name or "Permission" in name or "BadRequest" in name:
        return False

    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True

    if status_code in (429, 500, 502, 503, 504):
        return True

    msg_lower = str(exc).lower()
    retryable_words = ("rate", "quota", "timeout", "unavailable", "overloaded", "503", "429")
    return any(w in msg_lower for w in retryable_words)


def retry_with_backoff(
    fn: Callable[..., Any],
    max_retries: int,
    backoff_factor: float,
    sleeper: Callable[[float], None] = time.sleep,
) -> Any:
    """Executes a callable with exponential backoff and random jitter for retryable errors."""
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as exc:
            if attempt >= max_retries or not is_retryable_error(exc):
                raise
            attempt += 1
            delay = (backoff_factor**attempt) + random.uniform(0.05, 0.25)  # nosec B311 # noqa: S311
            sleeper(delay)
