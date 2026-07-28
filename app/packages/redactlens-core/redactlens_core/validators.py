"""Named validation functions usable from a detector's context boosters/suppressors.

A detector YAML can reference one of these by name (e.g. `validator: luhn`)
instead of a regex pattern, to run a real checksum/format check against the
matched text itself.
"""

from collections.abc import Callable


def luhn_valid(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn_valid,
}
