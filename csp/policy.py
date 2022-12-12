from __future__ import annotations

import logging
from collections import defaultdict

from django.core.cache import cache
from django.http import HttpRequest
from django.urls import reverse

from .models import CspRule, DirectiveChoices
from .settings import CSP_CACHE_TIMEOUT, PolicyType, get_default_rules

logger = logging.getLogger(__name__)

CACHE_KEY_RULES = "csp::rules"


def clear_cache() -> None:
    """Clear the cached CSP."""
    logger.debug("Clearing CSP cache")
    cache.delete(CACHE_KEY_RULES)


def refresh_rules_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Refreshing CSP cache")
    policy = build_policy()
    part_one = format_as_csp({k: v for k, v in policy.items() if k != "report-uri"})
    part_two = format_as_csp({k: v for k, v in policy.items() if k == "report-uri"})
    cache.set(CACHE_KEY_RULES, (part_one, part_two), CSP_CACHE_TIMEOUT)


def _dedupe(values: list[str]) -> list[str]:
    return list({CspRule.clean_value(v) for v in values})


def build_policy() -> PolicyType:
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
    policy: PolicyType = defaultdict(list)
    policy.update(get_default_rules())
    # returns list of additional (directive, value) tuples.
    new_rules = CspRule.objects.enabled().directive_values()
    # update the defaults with the additional rules.
    for directive, value in new_rules:
        if directive in DirectiveChoices.values:
            logger.debug('Adding "%s" to directive "%s"', value, directive)
            policy[directive].append(value)
        else:
            logger.debug('Ignoring unknown directive "%s"', directive)
    return {k: _dedupe(v) for k, v in policy.items()}


def format_as_csp(policy: PolicyType) -> str:
    """Convert policty dict into response header string."""
    directives = []
    for directive, values in policy.items():
        if not values:
            continue
        # combine values into a single space-delimited string
        value_str = " ".join(values)
        directives.append(f"{directive} {value_str}")
    # combine directives into a ";" delimited str - the CSP.
    return "; ".join(directives).strip()


def _context(request: HttpRequest) -> dict[str, str]:
    """Return report_uri and nonce."""
    context = {"report_uri": reverse("csp:report_uri")}
    if nonce := getattr(request, "csp_nonce", ""):
        context["nonce"] = f"'nonce-{nonce}'"
    return context


def get_csp(request: HttpRequest, add_report_uri: bool) -> str:
    """Fetch the CSP from the cache, or rebuild if it's missing."""
    if cached_csp := cache.get(CACHE_KEY_RULES):
        logger.debug("Found cached CSP (add report-uri: %s)", add_report_uri)
        csp = "; ".join(cached_csp) if add_report_uri else cached_csp[0]
        return csp.format(**_context(request))
    logger.debug("No cached CSP - rebuilding policy")
    refresh_rules_cache()
    return get_csp(request, add_report_uri)
