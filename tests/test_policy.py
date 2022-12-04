from unittest import mock

import pytest
from django.core.cache import cache
from django.test import RequestFactory

from csp.policy import CACHE_KEY, format_as_csp, get_csp


@pytest.mark.parametrize(
    "directive,value,output",
    [
        # empty directive is omitted
        ("script-src", [], ""),
        # empty report-uri is omitted
        ("script-src", ["'self'"], "script-src 'self'"),
    ],
)
def test_format_as_csp(directive, value, output):
    csp = {directive: value}
    assert format_as_csp(csp) == output


@pytest.mark.django_db
def test_get_csp(rf: RequestFactory):
    cache.delete(CACHE_KEY)
    request = rf.get("/")
    val = get_csp(request)
    assert CACHE_KEY in cache
    with mock.patch("csp.policy.refresh_cache") as mock_refresh:
        assert get_csp(request) == val
        mock_refresh.assert_not_called()
    cache.delete(CACHE_KEY)
