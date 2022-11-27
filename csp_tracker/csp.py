from __future__ import annotations

from django.core.cache import cache
from django.urls import reverse

from .models import CspRule
from .settings import CSP_CACHE_TIMEOUT, DEFAULT_RULES

CACHE_KEY = "csp"
DEFAULT_REPORT_URI = reverse("csp_report_uri")


def build_csp(report_uri: str = DEFAULT_REPORT_URI) -> str:
    rules = CspRule.objects.enabled().values_list("directive", "value").distinct()
    csp_rules = DEFAULT_RULES
    for directive, value in rules:
        csp_rules[directive].append(value)
    csp = []
    for directive, values in csp_rules.items():
        csp.append(f"{directive} {' '.join(set(values))}")
    csp.append(f"report-uri {report_uri}")
    return "; ".join(csp)


def get_csp() -> str:
    """Fetch the CSP from the cache, or rebuild if it's missing."""
    if csp := cache.get(CACHE_KEY):
        return csp
    refresh_cache()
    return get_csp()


def refresh_cache() -> None:
    """Refresh the cached CSP."""
    cache.set(CACHE_KEY, build_csp(), CSP_CACHE_TIMEOUT)
