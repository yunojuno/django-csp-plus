from __future__ import annotations

import logging
from collections import defaultdict

from django.core.cache import cache

from .models import CspRule
from .settings import CSP_CACHE_TIMEOUT, get_default_rules, get_report_uri

logger = logging.getLogger(__name__)

CACHE_KEY = "csp::rules"
CspDict = dict[str, list[str]]


def clear_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Clearing CSP cache")
    cache.delete(CACHE_KEY)


def refresh_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Refreshing CSP cache")
    cache.set(CACHE_KEY, build_csp(), CSP_CACHE_TIMEOUT)


def dedupe_expressions(values: list[str]) -> list[str]:
    return list({CspRule.clean_value(v) for v in values})


def build_csp() -> CspDict:
    """
    Build the CSP by combining default settings and CspRules.

    The CSP is a dict of directives and values. This function takes the
    default rules (from settings) and combines them with the CspRules
    from the database to create a cacheable object that represents the
    current state of the CSP.

    As part of building the CSP this function will also dedupe the
    values, and format any special values ('self', 'unsafe-inline',
    etc.) which must be formatted with the single-quotes.

    NB the CSP as cached is not quite complete - if the settings require
    a nonce to be added to any directives then this cannot be cached,
    and so the nonce is applied per-request.

    """
    logger.debug("Building new CSP")
    # return dict of {directive: [values]}
    csp_rules: CspDict = defaultdict(list)
    csp_rules.update(get_default_rules())
    # returns list of additional (directive, value) tuples.
    new_rules = CspRule.objects.enabled().directive_values()
    # update the defaults with the additional rules.
    for directive, value in new_rules:
        logger.debug('Adding "%s" to directive "%s"', value, directive)
        csp_rules[directive].append(value)
    # format and dedupe the values
    return {k: dedupe_expressions(v) for k, v in csp_rules.items()}


def format_csp_header(csp: CspDict, nonce: str | None = None) -> str:
    directives = []
    for directive, values in csp.items():
        if not values:
            continue
        # dedupe and recombine into a single space-delimited string
        value_str = " ".join(values)
        if nonce:
            value_str.replace("nonce", f"nonce-{nonce}")
        directives.append(f"{directive} {value_str}")
    # csp is now a list of directives - the report-uri comes last
    directives.append(f"report-uri {get_report_uri()}")
    return "; ".join(directives).strip()


def get_csp(nonce: str | None = None) -> str:
    """Fetch the CSP from the cache, or rebuild if it's missing."""
    if csp := cache.get(CACHE_KEY):
        logger.debug("Found cached CSP")
        return format_csp_header(csp, nonce)
    logger.debug("No cached CSP found")
    refresh_cache()
    return get_csp(nonce)
