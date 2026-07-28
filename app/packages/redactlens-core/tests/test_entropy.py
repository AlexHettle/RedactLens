from redactlens_core.methods.entropy import find_matches, shannon_entropy


def test_shannon_entropy_zero_for_repeated_char():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_entropy_higher_for_diverse_string():
    assert shannon_entropy("aB3fG7hK9mNpQ2rS") > shannon_entropy("aaaaaaaaaaaaaaaa")


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_find_matches_flags_high_entropy_token():
    text = "token = aB3fG7hK9mNpQ2rS5tUvWxYz8CdEeFg1 end"
    matches = list(find_matches(r"[A-Za-z0-9+/_=-]{20,64}", text, entropy_threshold=4.0))
    assert any(m.text == "aB3fG7hK9mNpQ2rS5tUvWxYz8CdEeFg1" for m in matches)


def test_find_matches_ignores_low_entropy_run():
    text = "repeat = aaaaaaaaaaaaaaaaaaaaaaaaaa end"
    matches = list(find_matches(r"[A-Za-z0-9+/_=-]{20,64}", text, entropy_threshold=4.0))
    assert matches == []
