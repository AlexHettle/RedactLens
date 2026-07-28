import math
from collections import Counter
from collections.abc import Iterator

from redactlens_core.methods import MatchCandidate
from redactlens_core.methods.regex import iter_pattern_matches


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. 0.0 for empty or single-character-repeated strings."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def find_matches(
    pattern: str,
    text: str,
    entropy_threshold: float,
    *,
    timeout_seconds: float | None = None,
    max_matches: int | None = None,
) -> Iterator[MatchCandidate]:
    """Find candidate tokens matching `pattern` (charset + length shape) whose
    Shannon entropy meets `entropy_threshold`. `pattern` carries the min-length
    and charset heuristics declaratively (e.g. `[A-Za-z0-9+/_=-]{20,64}`)."""
    for m in iter_pattern_matches(
        pattern,
        text,
        timeout_seconds=timeout_seconds,
        max_matches=max_matches,
    ):
        token = m.group(0)
        if shannon_entropy(token) >= entropy_threshold:
            yield MatchCandidate(start=m.start(), end=m.end(), text=token)
