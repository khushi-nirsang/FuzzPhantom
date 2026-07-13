from modules.subdomain import _extract_root, _valid_subdomain


def test_extract_root_from_full_url() -> None:
    assert _extract_root("https://www.dvago.pk/") == "dvago.pk"
    assert _extract_root("http://shop.example.co.uk/path") == "example.co.uk"


def test_valid_subdomain_filters_noise() -> None:
    assert _valid_subdomain("*.api.dvago.pk", "dvago.pk") == "api.dvago.pk"
    assert _valid_subdomain("dvago.pk", "dvago.pk") is None
    assert _valid_subdomain("evil-example.com", "dvago.pk") is None
