"""Shared retry policy for external calls (fixes the unused-tenacity gap).

Retries transient network/5xx errors with exponential backoff. Used by the
evidence S3 backend and connector HTTP helpers.
"""

from __future__ import annotations

import logging

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import settings

logger = logging.getLogger(__name__)


class TransientError(RuntimeError):
    """A retriable upstream failure (timeout, connection reset, 5xx)."""


def external_retry(func):
    """Decorator: retry on TransientError / requests transport errors."""
    return retry(
        retry=retry_if_exception_type((TransientError, requests.exceptions.ConnectionError,
                                       requests.exceptions.Timeout)),
        stop=stop_after_attempt(max(1, settings.retry_attempts)),
        wait=wait_exponential(multiplier=0.4, min=0.4, max=4),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )(func)
