from django.conf import settings

CSP_ENABLED = bool(getattr(settings, "CSP_ENABLED", False))


# If True then set the report-only attr on the CSP
CSP_REPORT_ONLY = bool(getattr(settings, "CSP_REPORT_ONLY", True))


# cache timeout in seconds - defaults to one hour
CSP_CACHE_TIMEOUT = int(getattr(settings, "CSP_CACHE_TIMEOUT", 3600))


# Default rules from https://content-security-policy.com/
DEFAULT_RULES: dict[str, list[str]] = getattr(
    settings,
    "CSP_DEFAULTS",
    {
        "default-src": ["none"],
        "base-uri": ["self"],
        "connect-src": ["self"],
        "form-action": ["self"],
        "img-src": ["self"],
        "script-src": ["self"],
        "style-src": ["self"],
    },
)
