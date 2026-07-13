from core.context import ScanContext
from modules.dir_fuzzer import _mutate_words


def test_word_mutation_adds_common_variants() -> None:
    ctx = ScanContext(target_domain="example.com", mutate_wordlist=True, mutate_depth=1)
    words = _mutate_words(["admin"], ctx)
    assert "admin" in words
    assert "ADMIN" in words
    assert "admin/" in words
    assert "admin.bak" in words
    assert "administrator" in words


def test_word_mutation_depth_two_adds_numeric_variants() -> None:
    ctx = ScanContext(target_domain="example.com", mutate_wordlist=True, mutate_depth=2)
    words = _mutate_words(["api"], ctx)
    assert "api2026" in words
    assert "api-2026" in words
    assert "api_2026" in words
