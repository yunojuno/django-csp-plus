from unittest import mock

import pytest
from django.core.cache import cache

from csp.policy import CACHE_KEY, format_csp_header, get_csp


@pytest.mark.parametrize(
    "directive,value,nonce,report_uri,output",
    [
        # empty directive is omitted
        ("script-src", [], None, "", ""),
        # empty report-uri is omitted
        ("script-src", ["'self'"], None, "", "script-src 'self'"),
        # report-uri is appended
        ("script-src", ["'self'"], None, "/uri", "script-src 'self'; report-uri /uri"),
        # nonce is injected
        ("script-src", ["nonce"], "123", "", "script-src nonce-123"),
    ],
)
def test_format_csp_header(directive, value, nonce, report_uri, output):
    csp = {directive: value}
    with mock.patch("csp.policy.get_report_uri", lambda: report_uri):
        assert format_csp_header(csp, nonce) == output


@pytest.mark.django_db
def test_get_csp():
    cache.delete(CACHE_KEY)
    val = get_csp()
    assert CACHE_KEY in cache
    with mock.patch("csp.policy.refresh_cache") as mock_refresh:
        assert get_csp() == val
        mock_refresh.assert_not_called()
    cache.delete(CACHE_KEY)
