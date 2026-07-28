from collections.abc import Iterator

from redactlens_core.methods import MatchCandidate


def find_matches(value: str, text: str, case_sensitive: bool = False) -> Iterator[MatchCandidate]:
    """Find literal (non-regex) occurrences of `value` in `text`.

    Used for built-in keyword detectors and, in Phase 2, runtime-injected
    user-defined literal targets. Matches don't overlap.
    """
    if not value:
        return
    haystack = text if case_sensitive else text.lower()
    needle = value if case_sensitive else value.lower()

    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return
        end = idx + len(value)
        yield MatchCandidate(start=idx, end=end, text=text[idx:end])
        start = end
