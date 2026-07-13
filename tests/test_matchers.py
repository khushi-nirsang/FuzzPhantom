from core.matchers import number_matches, parse_number_spec, regex_matches, validate_regex


def test_number_ranges_and_values() -> None:
    spec = parse_number_spec("200,300-302,404")
    assert spec is not None
    assert spec.matches(200)
    assert spec.matches(301)
    assert spec.matches(404)
    assert not spec.matches(500)


def test_number_matches_reversed_range() -> None:
    assert number_matches("403-401", 402)


def test_regex_helpers() -> None:
    assert validate_regex("admin|login")
    assert not validate_regex("[")
    assert regex_matches("admin", "GET /Admin HTTP/1.1")
