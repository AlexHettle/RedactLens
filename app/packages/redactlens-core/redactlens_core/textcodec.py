"""Text decoding shared by file reading, archive extraction, and the
anonymization writer.

UTF-8 plus anything that announces itself with a BOM (UTF-8-sig, UTF-16
LE/BE, UTF-32 LE/BE — PowerShell writes UTF-16 by default on Windows), with
a printability-gated Windows-1252 fallback for legacy single-byte files.
UTF-16 *without* a BOM can't be told apart from binary reliably, so it
stays undecodable.
"""

import codecs
from dataclasses import dataclass

BINARY_SNIFF_BYTES = 8000

# BOM -> codec, most-specific first: the UTF-32-LE BOM begins with the
# UTF-16-LE BOM, so checking 16 first would misread every UTF-32 file.
_BOM_CODECS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def codec_from_bom(raw: bytes) -> "TextCodec | None":
    """Return the announced codec without decoding the entire payload."""
    for bom, name in _BOM_CODECS:
        if raw.startswith(bom):
            return TextCodec(name, bom)
    return None


@dataclass(frozen=True)
class TextCodec:
    """How a text file was decoded — and how to write it back unchanged.

    Anonymization re-encodes with the same codec and re-prepends the same
    BOM, so a UTF-16 file stays a UTF-16 file after redacting.
    """

    name: str  # Python codec name
    bom: bytes = b""

    def encode(self, text: str) -> bytes:
        return self.bom + text.encode(self.name)


def decode_text(raw: bytes) -> tuple[str, TextCodec] | None:
    """(text, codec) when ``raw`` is readable text; None when it isn't.

    Tried in order: BOM-announced encodings, UTF-8, then Windows-1252 —
    the last only when the result actually looks like text, since almost
    any byte soup "decodes" as CP-1252.
    """
    for bom, name in _BOM_CODECS:
        if raw.startswith(bom):
            try:
                return raw[len(bom) :].decode(name), TextCodec(name, bom)
            except UnicodeDecodeError:
                return None  # the BOM promised an encoding the bytes don't honor
    if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
        return None
    try:
        return raw.decode("utf-8"), TextCodec("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        text = raw.decode("cp1252")
    except UnicodeDecodeError:
        return None
    if not mostly_printable(text):
        return None
    return text, TextCodec("cp1252")


def mostly_printable(text: str) -> bool:
    sample = text[:BINARY_SNIFF_BYTES]
    if not sample:
        return True
    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\t\n\r\f\v")
    return printable / len(sample) >= 0.9
