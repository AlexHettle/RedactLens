import ast
import json
from pathlib import Path

import pytest
from redactlens_core.anonymize import anonymize_files
from redactlens_core.models import ScanRequest
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan

CONNECTION = "postgres://admin:CorrectHorseBattery9@prod-db.internal:5432/appdb"
PUNCTUATED_CONNECTION = (
    "postgres://o'conn:p'ass@prod-db.internal:5432/team's/records"
    "?roles=read,write;mode=strict&redirect=/next?ok=yes#current"
)


def _scan_connection(path: Path):
    result = scan(ScanRequest(paths=[str(path)]), load_default_registry())
    return next(
        finding for finding in result.findings if finding.detector_id == "connection_string"
    )


def _redact(path: Path, source: str):
    path.write_text(source)
    finding = _scan_connection(path)
    output = Path(anonymize_files([finding])[str(path)])
    return finding, output.read_text()


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_python_connection_string_preserves_its_delimiter(tmp_path, quote):
    source = f"DATABASE_URL = {quote}{CONNECTION}{quote}\n"
    path = tmp_path / "config.py"
    finding, redacted = _redact(path, source)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset] == quote

    ast.parse(redacted)
    assert redacted == f"DATABASE_URL = {quote}{'*' * len(CONNECTION)}{quote}\n"


def test_compact_json_connection_string_preserves_following_delimiters(tmp_path):
    source = json.dumps(
        {"databaseUrl": CONNECTION, "enabled": True},
        separators=(",", ":"),
    )
    path = tmp_path / "config.json"
    finding, redacted = _redact(path, source)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset :].startswith('","enabled":true}')

    parsed = json.loads(redacted)

    assert parsed == {"databaseUrl": "*" * len(CONNECTION), "enabled": True}
    assert redacted.endswith('","enabled":true}')


def test_unwrapped_connection_uses_the_declared_bounded_next_key_lookahead(tmp_path):
    next_key = "k" * 255
    whitespace = " " * 32
    source = f'database_url: {CONNECTION},"{next_key}"{whitespace}: true\n'
    path = tmp_path / "config.yaml"
    path.write_text(source)

    finding = _scan_connection(path)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset :].startswith(f',"{next_key}"{whitespace}:')


@pytest.mark.parametrize(
    ("filename", "source", "suffix"),
    [
        (
            "config.yaml",
            f"{{database_url: {CONNECTION},enabled: true}}\n",
            ",enabled: true}\n",
        ),
        ("notes.md", f"Use `{CONNECTION}` for the local demo.\n", "` for the local demo.\n"),
        ("setup.sh", f"DATABASE_URL={CONNECTION}; echo ready\n", "; echo ready\n"),
        ("notes.txt", f"Connect with ({CONNECTION}).\n", ").\n"),
        ("notes.txt", f"Endpoint [{CONNECTION}] is healthy.\n", "] is healthy.\n"),
        ("config.yaml", f"{{database_url: {CONNECTION}}}\n", "}\n"),
    ],
)
def test_source_terminators_remain_outside_unwrapped_or_wrapped_values(
    tmp_path,
    filename,
    source,
    suffix,
):
    path = tmp_path / filename
    finding, redacted = _redact(path, source)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset :].startswith(suffix)
    assert redacted == source.replace(CONNECTION, "*" * len(CONNECTION))


def test_internal_apostrophes_and_query_subdelimiters_remain_in_the_value(tmp_path):
    source = f"DATABASE_URL={PUNCTUATED_CONNECTION}\n"
    path = tmp_path / ".env"

    finding, redacted = _redact(path, source)

    assert finding.matched_text == PUNCTUATED_CONNECTION
    assert redacted == f"DATABASE_URL={'*' * len(PUNCTUATED_CONNECTION)}\n"


def test_ipv6_host_is_complete_and_external_bracket_is_preserved(tmp_path):
    connection = "postgres://admin:secret@[2001:db8::7]:5432/app"
    source = f"Endpoint [{connection}] is healthy.\n"
    path = tmp_path / "notes.txt"

    finding, redacted = _redact(path, source)

    assert finding.matched_text == connection
    assert source[finding.end_offset :].startswith("] is healthy.\n")
    assert redacted == source.replace(connection, "*" * len(connection))


def test_compact_single_quoted_expression_stops_at_the_first_source_closer(tmp_path):
    source = f"url='{CONNECTION}';x='foo'\n"
    path = tmp_path / "config.py"

    finding, redacted = _redact(path, source)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset :].startswith("';x='foo'\n")
    assert redacted == f"url='{'*' * len(CONNECTION)}';x='foo'\n"
    ast.parse(redacted)


def test_single_quote_wrapper_retains_an_internal_path_apostrophe(tmp_path):
    connection = "postgres://admin:secret@db.internal/team's/records"
    source = f"Use '{connection}'; then rotate it.\n"
    path = tmp_path / "notes.txt"

    finding, redacted = _redact(path, source)

    assert finding.matched_text == connection
    assert source[finding.end_offset :].startswith("'; then rotate it.\n")
    assert redacted == source.replace(connection, "*" * len(connection))


def test_bare_sentence_ending_period_remains_outside_the_value(tmp_path):
    source = f"DATABASE_URL={CONNECTION}.\n"
    path = tmp_path / ".env"

    finding, redacted = _redact(path, source)

    assert finding.matched_text == CONNECTION
    assert source[finding.end_offset :].startswith(".\n")
    assert redacted == f"DATABASE_URL={'*' * len(CONNECTION)}.\n"
