from src.argus.utils import normalize_url

def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "https://example.com"

def test_normalize_url_keeps_existing_scheme():
    assert normalize_url("http://test.com") == "http://test.com"
    assert normalize_url("https://secure.com") == "https://secure.com"
