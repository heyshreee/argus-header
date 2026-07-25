from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme (default to https)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url

