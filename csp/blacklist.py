from __future__ import annotations

import logging

from django.core.cache import cache

from .models import CspReport, CspReportBlacklist
from .settings import CSP_CACHE_TIMEOUT

logger = logging.getLogger(__name__)
PolicyType = dict[str, list[str]]

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


def get_blacklist() -> PolicyType:
    """Fetch the CSP blacklist from cache."""
    # must check against None as default blacklist is falsey {}
    if (blacklist := cache.get(CACHE_KEY_BLACKLIST)) is not None:
        return blacklist
    refresh_cache()
    return get_blacklist()


def is_blacklisted(report: CspReport) -> bool:
    """Return True if the report should be ignored."""
    blacklist = get_blacklist()
    return report.blocked_uri in blacklist.get(report.effective_directive, {})
