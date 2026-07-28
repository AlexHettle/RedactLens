"""Candidate-extraction methods: turn raw text into match candidates.

Each method (regex, keyword, entropy) takes a detector's `pattern` field and
the text being scanned, and yields MatchCandidate spans. Confidence scoring
happens later, in scoring.py — these methods only find *where* something
might be, not whether it's sensitive.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MatchCandidate:
    start: int
    end: int
    text: str
