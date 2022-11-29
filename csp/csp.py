from __future__ import annotations

from django.core.cache import cache

from .models import CspRule
from .settings import CSP_CACHE_TIMEOUT, CSP_REPORT_URI, DEFAULT_RULES

CACHE_KEY = "csp::rules"


def build_csp() -> str:
    rules = CspRule.objects.enabled().values_list("directive", "value").distinct()
    csp_rules = DEFAULT_RULES
    for directive, value in rules:
        csp_rules[directive].append(value)
    csp = []
    for directive, values in csp_rules.items():
        if not values:
            continue
        value_str = " ".join(sorted(values))
        csp.append(f"{directive} {value_str}")
    csp.append(f"report-uri {CSP_REPORT_URI}")
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
