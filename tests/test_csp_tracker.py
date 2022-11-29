from unittest import mock

import pytest
from django.core.cache import cache

from csp import csp
from csp import settings as csp_settings


@pytest.mark.django_db
class TestCsp:
    def test_default_csp(self):
        assert csp.build_csp() == (
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
                    f"report-uri {csp_settings.CSP_REPORT_URI}",
                ]
            )
        )

    @mock.patch("csp.csp.DEFAULT_RULES", {})
    def test_build_csp(self):
        assert csp.build_csp() == f"report-uri {csp_settings.CSP_REPORT_URI}"

    def test_get_csp(self):
        cache.delete(csp.CACHE_KEY)
        val = csp.get_csp()
        assert csp.CACHE_KEY in cache
        with mock.patch("csp.csp.refresh_cache") as mock_refresh:
            assert csp.get_csp() == val
            mock_refresh.assert_not_called()
        cache.delete(csp.CACHE_KEY)
