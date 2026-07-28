from __future__ import annotations

import math
from collections.abc import Iterator
from functools import lru_cache

import regex as regex_engine

from redactlens_core.methods import MatchCandidate

_QUOTE_CHARS = ('"', "'")
DEFAULT_REGEX_TIMEOUT_SECONDS = 0.5
DEFAULT_REGEX_MATCH_LIMIT = 100_000


class RegexSafetyError(RuntimeError):
    """A regex evaluation stopped at a configured resource boundary."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


class RegexEvaluationTimedOut(RegexSafetyError):
    def __init__(self) -> None:
        super().__init__(
            "regex_timeout",
            "regex evaluation exceeded the configured safety deadline",
        )


class RegexMatchLimitExceeded(RegexSafetyError):
    def __init__(self) -> None:
        super().__init__(
            "regex_match_limit",
            "regex evaluation produced too many candidate matches",
        )


@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> regex_engine.Pattern:
    """Compile with the same compatibility mode used during validation."""
    return regex_engine.compile(pattern, regex_engine.VERSION0)


def iter_pattern_matches(
    pattern: str,
    text: str,
    *,
    timeout_seconds: float | None = None,
    max_matches: int | None = None,
) -> Iterator[regex_engine.Match]:
    """Yield matches while enforcing both execution-time and result-count bounds."""
    timeout = _validated_timeout(timeout_seconds)
    match_limit = _validated_match_limit(max_matches)
    compiled = compile_pattern(pattern)
    try:
        for match_number, match in enumerate(
            compiled.finditer(text, timeout=timeout, concurrent=True),
            start=1,
        ):
            if match_number > match_limit:
                raise RegexMatchLimitExceeded
            yield match
    except TimeoutError as error:
        raise RegexEvaluationTimedOut from error


def search_pattern(
    pattern: str,
    text: str,
    *,
    timeout_seconds: float | None = None,
) -> bool:
    """Return whether a pattern matches without permitting unbounded evaluation."""
    timeout = _validated_timeout(timeout_seconds)
    try:
        return compile_pattern(pattern).search(text, timeout=timeout, concurrent=True) is not None
    except TimeoutError as error:
        raise RegexEvaluationTimedOut from error


def find_matches(
    pattern: str,
    text: str,
    *,
    timeout_seconds: float | None = None,
    max_matches: int | None = None,
) -> Iterator[MatchCandidate]:
    """Find candidates for a regex-method detector.

    If the pattern defines a named group `value`, that group's span is used
    as the candidate (lets a detector match a whole `key = value` assignment
    for context while only flagging the value itself). Otherwise the full
    match is used. A value wrapped in a single matching pair of quotes has
    the quotes stripped.
    """
    compiled = compile_pattern(pattern)
    for m in iter_pattern_matches(
        pattern,
        text,
        timeout_seconds=timeout_seconds,
        max_matches=max_matches,
    ):
        if "value" in compiled.groupindex and m.group("value") is not None:
            start, end = m.span("value")
        else:
            start, end = m.span(0)

        if end - start >= 2 and text[start] in _QUOTE_CHARS and text[end - 1] == text[start]:
            start, end = start + 1, end - 1

        yield MatchCandidate(start=start, end=end, text=text[start:end])


def _validated_timeout(timeout_seconds: float | None) -> float:
    timeout = DEFAULT_REGEX_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("regex timeout must be a finite positive number")
    return timeout


def _validated_match_limit(max_matches: int | None) -> int:
    match_limit = DEFAULT_REGEX_MATCH_LIMIT if max_matches is None else max_matches
    if isinstance(match_limit, bool) or not isinstance(match_limit, int) or match_limit <= 0:
        raise ValueError("regex match limit must be a positive integer")
    return match_limit
