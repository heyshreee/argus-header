import socket

import pytest

from argus_header.url_safety import UnsafeTargetError, validate_public_http_url


def test_rejects_localhost_without_resolving_dns():
    with pytest.raises(UnsafeTargetError):
        validate_public_http_url("http://127.0.0.1:8000")


def test_rejects_non_http_scheme():
    with pytest.raises(UnsafeTargetError):
        validate_public_http_url("file:///etc/passwd")


def test_rejects_hostname_with_private_dns_answer(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))
        ],
    )
    with pytest.raises(UnsafeTargetError):
        validate_public_http_url("https://example.test")


def test_allows_hostname_with_public_dns_answer(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        ],
    )
    validate_public_http_url("https://example.test")
