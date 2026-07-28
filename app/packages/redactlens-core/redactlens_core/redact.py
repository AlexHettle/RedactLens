MASK_CHAR = "*"
MAX_PREVIEW_LENGTH = 32


def redacted_preview(text: str, keep_start: int = 2, keep_end: int = 2) -> str:
    """Mask the middle of `text`, keeping a few edge characters for context.

    Used for `Finding.redacted_preview` so a raw secret never has to be
    displayed (or logged) in full. Long values are capped so a complete key
    block or token cannot overwhelm CLI and UI result layouts.
    """
    if len(text) <= keep_start + keep_end:
        return MASK_CHAR * len(text)
    masked_len = min(
        len(text) - keep_start - keep_end,
        max(1, MAX_PREVIEW_LENGTH - keep_start - keep_end),
    )
    return text[:keep_start] + MASK_CHAR * masked_len + text[len(text) - keep_end :]
