from __future__ import annotations

from django.core.cache import cache
from django.urls import reverse

from .models import CspRule
from .settings import DEFAULT_RULES

CACHE_KEY = "csp"
DEFAULT_REPORT_URI = reverse("csp_report_uri")


def build_csp(report_uri: str = DEFAULT_REPORT_URI) -> str:
    rules = CspRule.objects.enabled().values_list("directive", "value").distinct()
    csp_rules = DEFAULT_RULES
    for directive, value in rules:
        csp_rules[directive].append(value)
    csp = []
    for directive, values in csp_rules.items():
        csp.append(f"{directive} {' '.join(values)}")
    csp.append(f"report-uri {report_uri}")
    return "; ".join(csp)


def get_csp() -> str:
    if csp := cache.get(CACHE_KEY):
        return csp
    csp = build_csp()
    cache.set(CACHE_KEY, csp, 1)
    return get_csp()
