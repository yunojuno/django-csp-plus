from unittest import mock

import pytest
from django.core.cache import cache
from django.test import RequestFactory

from csp.policy import CACHE_KEY_RULES, format_as_csp, get_csp


@pytest.mark.parametrize(
    "directive,value,output",
    [
        # empty directive is omitted
        ("script-src", [], ""),
        # empty report-uri is omitted
        ("script-src", ["'self'"], "script-src 'self'"),
    ],
)
def test_format_as_csp(directive: str, value: list[str], output: str) -> None:
    csp = {directive: value}
    assert format_as_csp(csp) == output


@pytest.mark.django_db
def test_get_csp(rf: RequestFactory) -> None:
    cache.delete(CACHE_KEY_RULES)
    request = rf.get("/")
    val = get_csp(request, True)
    assert CACHE_KEY_RULES in cache
    with mock.patch("csp.policy.refresh_rules_cache") as mock_refresh:
        assert get_csp(request, True) == val
        mock_refresh.assert_not_called()
    cache.delete(CACHE_KEY_RULES)
