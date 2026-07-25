from src.argus.requester import fetch_headers

def test_fetch_headers_success():
    result = fetch_headers("https://example.com")

    assert result["success"] is True
    assert "status_code" in result
    assert "headers" in result
    assert isinstance(result["headers"], dict)

def test_fetch_headers_failure():
    # Invalid URL
    result = fetch_headers("http://nonexistent.1234567890")

    assert result["success"] is False
    assert "error" in result
