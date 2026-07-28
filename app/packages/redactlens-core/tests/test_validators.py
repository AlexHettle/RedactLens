from redactlens_core.validators import luhn_valid


def test_luhn_valid_for_known_test_card_number():
    assert luhn_valid("4111111111111111") is True


def test_luhn_valid_handles_separators():
    assert luhn_valid("4111-1111-1111-1111") is True


def test_luhn_invalid_for_bad_checksum():
    assert luhn_valid("4111111111111112") is False


def test_luhn_invalid_for_too_short():
    assert luhn_valid("411111") is False
