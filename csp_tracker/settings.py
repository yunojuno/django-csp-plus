from django.conf import settings

CSP_ENABLED = getattr(settings, "CSP_ENABLED", False)

DEFAULT_RULES: dict[str, list[str]] = getattr(settings, "CSP_DEFAULTS", {})
DEFAULT_RULES.setdefault("child-src", ["'self'"])
DEFAULT_RULES.setdefault("connect-src", ["'self'"])
DEFAULT_RULES.setdefault("default-src", ["'self'"])
DEFAULT_RULES.setdefault("font-src", ["'self'", "'unsafe-inline'"])
DEFAULT_RULES.setdefault("frame-src", ["'self'"])
DEFAULT_RULES.setdefault("img-src", ["'self'"])
DEFAULT_RULES.setdefault("manifest-src", ["'self'"])
DEFAULT_RULES.setdefault("media-src", ["'self'"])
DEFAULT_RULES.setdefault("object-src", ["'self'"])
DEFAULT_RULES.setdefault("script-src", ["'self'", "'unsafe-inline'"])
DEFAULT_RULES.setdefault("style-src", ["'self'", "'unsafe-inline'"])
DEFAULT_RULES.setdefault("worker-src", ["'self'"])
