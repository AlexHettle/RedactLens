from redactlens_core.methods import keyword, regex


def test_regex_find_matches_whole_match_by_default():
    candidates = list(regex.find_matches(r"\d{3}-\d{2}-\d{4}", "ssn: 123-45-6789 end"))
    assert len(candidates) == 1
    assert candidates[0].text == "123-45-6789"
    assert candidates[0].start == 5
    assert candidates[0].end == 16


def test_regex_find_matches_uses_named_value_group():
    pattern = r"password\s*=\s*(?P<value>\S+)"
    candidates = list(regex.find_matches(pattern, "password=hunter2"))
    assert len(candidates) == 1
    assert candidates[0].text == "hunter2"


def test_regex_strips_matching_surrounding_quotes_from_value():
    pattern = r"password\s*=\s*(?P<value>\S+)"
    candidates = list(regex.find_matches(pattern, 'password="hunter2"'))
    assert candidates[0].text == "hunter2"


def test_keyword_find_matches_case_insensitive_by_default():
    candidates = list(keyword.find_matches("acme-corp-12345", "My account is ACME-CORP-12345 ok"))
    assert len(candidates) == 1
    assert candidates[0].text == "ACME-CORP-12345"


def test_keyword_find_matches_non_overlapping():
    candidates = list(keyword.find_matches("aa", "aaaa"))
    assert len(candidates) == 2
