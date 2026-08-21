import pytest

from vulnscan.utils import parse_target


def test_bare_host_defaults_to_https_443():
    t = parse_target("example.com")
    assert t.scheme == "https"
    assert t.host == "example.com"
    assert t.port == 443
    assert t.base_url == "https://example.com"


def test_explicit_http_scheme():
    t = parse_target("http://example.com")
    assert t.scheme == "http"
    assert t.port == 80
    assert t.base_url == "http://example.com"


def test_nonstandard_port_kept_in_base_url():
    t = parse_target("http://example.com:8080")
    assert t.port == 8080
    assert t.base_url == "http://example.com:8080"


def test_path_is_ignored_for_host_parsing():
    t = parse_target("https://example.com/some/path")
    assert t.host == "example.com"
    assert t.port == 443


def test_invalid_target_raises():
    with pytest.raises(ValueError):
        parse_target("not a url @@@")
