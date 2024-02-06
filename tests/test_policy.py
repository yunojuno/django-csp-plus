from unittest import mock

import pytest
from django.core.cache import cache
from django.test import RequestFactory

from csp.policy import CACHE_KEY_RULES, _dedupe, _downgrade, format_as_csp, get_csp
from csp.settings import CSP_REPORT_DIRECTIVE_DOWNGRADE


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


def test__downgrade() -> None:
    assert CSP_REPORT_DIRECTIVE_DOWNGRADE["script-src-elem"] == "script-src"
    assert _downgrade("script-src-elem") == "script-src"
    assert _downgrade("made-up-directive") == "made-up-directive"


@pytest.mark.parametrize(
    "input_list,output_list",
    [
        ([], []),
        (["'self'"], ["'self'"]),
        (["'none'"], ["'none'"]),
        (["'none'", "'self'"], ["'self'"]),
    ],
)
def test__dedupe(input_list: list[str], output_list: list[str]) -> None:
    """
    Test for console error when default-src is 'none' and has values.

        The Content-Security-Policy directive 'default-src' contains the
        keyword 'none' alongside with other source expressions. The
        keyword 'none' must be the only source expression in the
        directive value, otherwise it is ignored.

    This same issue affects all directives that have 'none' as a value,
    and so we fix it in the _dedupe function.

    """
    assert _dedupe(input_list) == output_list
