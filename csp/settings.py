from copy import deepcopy

from django.conf import settings
from django.http import HttpRequest, HttpResponse

# If False then the middleware is disabled completely
CSP_ENABLED = bool(getattr(settings, "CSP_ENABLED", False))


# If True then set the report-only attr on the CSP
CSP_REPORT_ONLY = bool(getattr(settings, "CSP_REPORT_ONLY", True))


# cache timeout in seconds - defaults to one hour
CSP_CACHE_TIMEOUT = int(getattr(settings, "CSP_CACHE_TIMEOUT", 3600))


# directives to which "nonce-rAnd0m" will be appended
CSP_ADD_NONCE_DIRECTIVES: list[str] = getattr(settings, "CSP_ADD_NONCE_DIRECTIVES", [])


# default func to apply CSP to HTML docs only.
def _apply_csp_header(request: HttpRequest, response: HttpResponse) -> bool:
    return "text/html" in response.headers.get("content-type", "")


# True if the request should have the header; defaults to HTML pages only.
apply_csp_header = getattr(settings, "CSP_APPLY_HEADER_FUNC", _apply_csp_header)


# Name of the header value to use based on CSP_REPORT_ONLY
def get_response_header() -> str:
    return {
        True: "Content-Security-Policy-Report-Only",
        False: "Content-Security-Policy",
    }[CSP_REPORT_ONLY]


# # default report-uri is this app, but can be overridden
# def get_report_uri() -> str:
#     return getattr(settings, "CSP_REPORT_URI", reverse("csp:report_uri"))


# Default rules from https://content-security-policy.com/
def get_default_rules() -> dict[str, list[str]]:
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
