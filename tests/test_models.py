import pytest

from csp.models import CspRule


@pytest.mark.parametrize(
    "input,output",
    [
        ("", ""),
        # add single quotes
        ("nonce", "'nonce'"),
        ("none", "'none'"),
        ("report-sample", "'report-sample'"),
        ("self", "'self'"),
        ("strict-dynamic", "'strict-dynamic'"),
        ("unsafe-eval", "'unsafe-eval'"),
        ("unsafe-hashes", "'unsafe-hashes'"),
        ("unsafe-inline", "'unsafe-inline'"),
        ("wasm-unsafe-eval", "'wasm-unsafe-eval'"),
        # add unsafe and single quotes
        ("inline", "'unsafe-inline'"),
        # add trailing colon
        ("data", "data:"),
        ("mediastream", "mediastream:"),
        ("blob", "blob:"),
        ("filesystem", "filesystem:"),
        # source schemes
        ("https://*.example.com", "https://*.example.com"),
        ("https://*.example.com?foo=bar", "https://*.example.com"),
        ("mail.example.com:443", "mail.example.com:443"),
        ("https://store.example.com", "https://store.example.com"),
        ("ws://example.com", "ws://example.com"),
    ],
)
def test_clean_value(input, output) -> None:
    assert CspRule.clean_value(input) == output
