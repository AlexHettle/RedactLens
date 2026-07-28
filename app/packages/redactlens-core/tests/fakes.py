"""Shared test doubles for redactlens-core tests."""

from redactlens_core.llm.adapter import LLMVerdict


class FakeAdapter:
    """Stands in for OllamaAdapter -- returns a scripted verdict per prompt,
    without any real network call."""

    def __init__(self, verdict: LLMVerdict | None = None, available: bool = True):
        self._verdict = verdict
        self._available = available
        self.calls: list[str] = []

    def available(self) -> bool:
        return self._available

    def judge(self, question: str) -> LLMVerdict | None:
        self.calls.append(question)
        return self._verdict(question) if callable(self._verdict) else self._verdict
