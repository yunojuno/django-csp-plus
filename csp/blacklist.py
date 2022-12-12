from __future__ import annotations

import logging

from django.core.cache import cache

from .models import CspReportBlacklist, ReportData
from .settings import CSP_CACHE_TIMEOUT, PolicyType

logger = logging.getLogger(__name__)

CACHE_KEY_BLACKLIST = "csp::blacklist"


def clear_cache() -> None:
    """Clear the cached blacklist."""
    logger.debug("Clearing CSP blacklist cache")
    cache.delete(CACHE_KEY_BLACKLIST)


def refresh_cache() -> None:
    """Refresh the cached blacklist."""
    logger.debug("Refreshing CSP blacklist cache")
    blacklist = CspReportBlacklist.objects.all().as_dict()
    cache.set(CACHE_KEY_BLACKLIST, blacklist, CSP_CACHE_TIMEOUT)


def get_blacklist(directive: str) -> PolicyType:
    """Fetch the CSP blacklist from cache."""
    # must check against None as default blacklist is falsey {}
    if (blacklist := cache.get(CACHE_KEY_BLACKLIST)) is not None:
        return blacklist.get(directive, [])
    refresh_cache()
    return get_blacklist(directive)


def is_blacklisted(report: ReportData) -> bool:
    """Return True if the report should be ignored."""
    # blacklist anything that doesn't have an effective_directive
    if not report.effective_directive:
        return True
    blacklisted_sources = get_blacklist(report.effective_directive)
    return any([b for b in blacklisted_sources if report.blocked_uri.startswith(b)])
