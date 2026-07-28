from redactlens_core.redact import MAX_PREVIEW_LENGTH, redacted_preview


def test_redacted_preview_preserves_short_value_shape():
    assert redacted_preview("123-45-6789") == "12*******89"


def test_redacted_preview_caps_long_values_without_exposing_the_middle():
    secret = "AB" + "sensitive" * 30 + "YZ"

    preview = redacted_preview(secret)

    assert preview == "AB" + "*" * 28 + "YZ"
    assert len(preview) == MAX_PREVIEW_LENGTH
    assert "sensitive" not in preview
