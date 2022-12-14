from __future__ import annotations

from copy import deepcopy
from typing import Callable, TypeAlias

from django.conf import settings
from django.http import HttpRequest, HttpResponse

PolicyType: TypeAlias = dict[str, list[str]]


# If False then the middleware is disabled completely
CSP_ENABLED = bool(getattr(settings, "CSP_ENABLED", False))


# If True then set the report-only attr on the CSP
CSP_REPORT_ONLY = bool(getattr(settings, "CSP_REPORT_ONLY", True))

# === reporting ===
#
# This is complicated - the reporting process is in a state of flux, and
# there are three scenarios to support in order to handle today's
# browsers and the newer, propoosed standards.
#
# Phase 1 (today): reporting uses the "report-uri <uri>"  CSP directive
#
# Phase 2 (today (partial)): reporting uses the "report-to <endpoint>"
# SCP directive, which in turn relies on the browser reporting API.
#
# Phase 2.1 the reporting API uses the "Report-To" HTTP header
#
# Phase 2.2 the reporting API uses the new "Reporting-Endpoints" header.
#
# We make no attempt to control this - but we do provide support for the
# reporting API headers - if you supply them, we'll add them.
#
# See https://developer.chrome.com/blog/reporting-api-migration/#migration-steps-for-csp-reporting  # noqa: E501
# for a migration plan, and https://www.w3.org/TR/reporting-1/ for the spec.


# The Report-To header value - if supplied it will be added to the response -
# and you can then add a "report-to: <endpoint>" directive to the CSP.
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to  # noqa: E501
REPORT_TO_HEADER = getattr(settings, "REPORT_TO_HEADER", None)


# The Reporting-Endpoints value - if supplied it will be added to the response -
# and you can then add a "report-to: <endpoint>" directive to the CSP.
# https://developer.chrome.com/blog/reporting-api-migration/#migration-steps-for-csp-reporting  # noqa: E501
REPORTING_ENDPOINTS_HEADER = getattr(settings, "REPORTING_ENDPOINTS_HEADER", None)


# Value 0..1 - used to tune the percentage of responses that get the
# report-uri valuable if the reporting is too noisy. Set to 0.0 to
# disable report-uri completely, or 1.0 to include it on all responses.
CSP_REPORT_SAMPLING = float(getattr(settings, "CSP_REPORT_SAMPLING", 1.0))


# Value 0..1 - used to throttle report-uri requests. The report-uri is
# an open endpoint that accepts JSON payloads - and as such represents a
# DOS vulnerability. Use this to throw away a percentage of reports
# received without attempting to process them. Set to 1.0 to ignore all
# inbound reports.
CSP_REPORT_THROTTLING = float(getattr(settings, "CSP_REPORT_THROTTLING", 0.0))


# dict to downgrade unsupported directives when converting to rules,
# e.g. if the violation from Chrome is "script-src-elem", which is not
# universally supported, then convert it to "script-src" on the fly.
CSP_REPORT_DIRECTIVE_DOWNGRADE: dict[str, str] = getattr(
    settings,
    "CSP_REPORT_DIRECTIVE_MAP",
    {
        "script-src-elem": "script-src",
        "script-src-attr": "script-src",
        "style-src-elem": "style-src",
        "style-src-attr": "style-src",
    },
)


# Name of the header value to use based on CSP_REPORT_ONLY
CSP_RESPONSE_HEADER = {
    True: "Content-Security-Policy-Report-Only",
    False: "Content-Security-Policy",
}[CSP_REPORT_ONLY]


# cache timeout in seconds - defaults to one hour
CSP_CACHE_TIMEOUT = int(getattr(settings, "CSP_CACHE_TIMEOUT", 3600))


# default process_request func
def _process_request(request: HttpRequest) -> bool:
    return True


# default process_response funct
def _process_response(response: HttpResponse) -> bool:
    return "text/html" in response.headers.get("content-type", "")


# True if the request should have the header; defaults to HTML pages only.
process_request: Callable[[HttpRequest], bool] = getattr(
    settings, "CSP_FILTER_REQUEST_FUNC", _process_request
)


process_response: Callable[[HttpResponse], bool] = getattr(
    settings, "CSP_FILTER_RESPONSE_FUNC", _process_response
)


# Default rules from https://content-security-policy.com/
def get_default_rules() -> PolicyType:
    if defaults := getattr(settings, "CSP_DEFAULTS", None):
        # if we don't return a deepcopy alterations to the
        # dictionary will update the lists, meaning that
        # values get stuck.
        return deepcopy(defaults)
    return {
        "default-src": ["'none'"],
        "base-uri": ["'self'"],
        "connect-src": ["'self'"],
        "form-action": ["'self'"],
        "font-src": ["'self'"],
        "img-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "report-uri": ["{report_uri}"],
    }
