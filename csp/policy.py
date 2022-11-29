from __future__ import annotations

import logging

from django.core.cache import cache

from .models import CspRule
from .settings import CSP_CACHE_TIMEOUT, get_default_rules, get_report_uri

logger = logging.getLogger(__name__)

CACHE_KEY = "csp::rules"


def clear_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Clearing CSP cache")
    cache.delete(CACHE_KEY)


def refresh_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Refreshing CSP cache")
    cache.set(CACHE_KEY, build_csp(), CSP_CACHE_TIMEOUT)


def build_csp() -> str:
    """Build the CSP by combining default settings and CspRules."""
    logger.debug("Building new CSP")
    # return dict of {directive: [values]}
    csp_rules = get_default_rules()
    # returns list of additional (directive, value) tuples.
    new_rules = CspRule.objects.enabled().directive_values()
    # update the defaults with the additional rules.
    for directive, value in new_rules:
        logger.debug("Adding '%s' to directive '%s'", value, directive)
        csp_rules[directive].append(value)
    csp = []
    # at this point we have a dict of {directive: [values]} which we
    # need to convert into the CSP format.
    for directive, values in csp_rules.items():
        if not values:
            continue
        # dedupe and recombine into a single space-delimited string
        value_str = " ".join(set(values))
        csp.append(f"{directive} {value_str}")
    # csp is now a list of directives - the report-uri comes last
    csp.append(f"report-uri {get_report_uri()}")
    return "; ".join(csp)


def get_csp() -> str:
    """Fetch the CSP from the cache, or rebuild if it's missing."""
    if csp := cache.get(CACHE_KEY):
        logger.debug("Found cached CSP")
        return csp
    logger.debug("No cached CSP found")
    refresh_cache()
    return get_csp()
