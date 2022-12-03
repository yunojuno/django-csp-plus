from unittest import mock

import pytest
from django.core.cache import cache

from csp import policy


@pytest.mark.django_db
class TestCsp:
    def test_get_csp(self):
        cache.delete(policy.CACHE_KEY)
        val = policy.get_csp()
        assert policy.CACHE_KEY in cache
        with mock.patch("csp.policy.refresh_cache") as mock_refresh:
            assert policy.get_csp() == val
            mock_refresh.assert_not_called()
        cache.delete(policy.CACHE_KEY)
