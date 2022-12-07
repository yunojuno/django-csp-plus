from __future__ import annotations

import logging
import random
from collections import defaultdict

from django.core.cache import cache
from django.http import HttpRequest
from django.urls import reverse

from .models import CspRule, DirectiveChoices
from .settings import CSP_CACHE_TIMEOUT, CSP_REPORT_SAMPLING, get_default_rules

logger = logging.getLogger(__name__)

CACHE_KEY = "csp::rules"
PolicyType = dict[str, list[str]]


def clear_cache() -> None:
    """Clear the cached CSP."""
    logger.debug("Clearing CSP cache")
    cache.delete(CACHE_KEY)


def refresh_cache() -> None:
    """Refresh the cached CSP."""
    logger.debug("Refreshing CSP cache")
    policy = build_policy()
    csp_header = format_as_csp(policy)
    cache.set(CACHE_KEY, csp_header, CSP_CACHE_TIMEOUT)


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
    # format and dedupe the values
    return {k: _dedupe(v) for k, v in policy.items()}


def format_as_csp(policy: PolicyType) -> str:
    """Convert policty dict into response header string."""
    directives = []
    for directive, values in policy.items():
        if not values:
            continue
        # dedupe and recombine into a single space-delimited string
        value_str = " ".join(values)
        directives.append(f"{directive} {value_str}")
    # csp is now a list of directives
    return "; ".join(directives).strip()


def _context(request: HttpRequest) -> dict[str, str]:
    """Return report_uri and nonce."""
    context = {"report_uri": reverse("csp:report_uri")}
    if nonce := getattr(request, "csp_nonce", ""):
        context["nonce"] = f"'nonce-{nonce}'"
    # CSP_REPORT_SAMPLING is a float 0..1 - if we're above the value,
    # then strip out the report-uri so that we don't send reports.
    if random.random() > CSP_REPORT_SAMPLING:  # noqa: S311
        logger.debug("Removing report_uri from CSP (sampling)")
        context["report_uri"] = ""
    return context


def get_csp(request: HttpRequest) -> str:
    """Fetch the CSP from the cache, or rebuild if it's missing."""
    if csp := cache.get(CACHE_KEY):
        logger.debug("Found cached CSP")
        return csp.format(**_context(request))
    logger.debug("No cached CSP - rebuilding policy")
    refresh_cache()
    return get_csp(request)
