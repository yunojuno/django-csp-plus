from unittest import mock

import pytest
from django.core.cache import cache

from csp import policy
from csp import settings as csp_settings


@pytest.mark.django_db
class TestCsp:
    def test_default_csp(self):
        assert policy.build_csp() == (
            "; ".join(
                [
                    "child-src 'self'",
                    "connect-src 'self'",
                    "default-src 'self'",
                    "font-src 'self' 'unsafe-inline'",
                    "frame-src 'self'",
                    "img-src 'self'",
                    "manifest-src 'self'",
                    "media-src 'self'",
                    "object-src 'self'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "worker-src 'self'",
                    f"report-uri {csp_settings.get_report_uri()}",
                ]
            )
        )

    def test_get_csp(self):
        cache.delete(policy.CACHE_KEY)
        val = policy.get_csp()
        assert policy.CACHE_KEY in cache
        with mock.patch("csp.policy.refresh_cache") as mock_refresh:
            assert policy.get_csp() == val
            mock_refresh.assert_not_called()
        cache.delete(policy.CACHE_KEY)
