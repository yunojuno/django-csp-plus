from unittest import mock

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from csp.middleware import CspHeaderMiddleware

TEST_REPORT_TO = {
    "group": "endpoint-1",
    "max_age": 10886400,
    "endpoints": [{"url": "https://backup.com/reports"}],
}

TEST_REPORTING_ENDPOINTS = "endpoint-1=https://backup.com/reports"


@pytest.mark.django_db
class TestCspHeaderMiddleware:
    def middleware(self) -> CspHeaderMiddleware:
        return CspHeaderMiddleware(lambda r: HttpResponse())

    @pytest.mark.parametrize(
        "report_to,has_header", [(None, False), ({}, False), (TEST_REPORT_TO, True)]
    )
    def test_report_to(
        self, rf: RequestFactory, report_to: dict, has_header: bool
    ) -> None:
        request = rf.get("/")
        with mock.patch("csp.middleware.REPORT_TO_HEADER", report_to):
            response: HttpResponse = self.middleware()(request)
        assert response.has_header("Report-To") == has_header
        assert response.has_header("Reporting-Endpoints") is False

    @pytest.mark.parametrize(
        "reporting_endpoints,has_header",
        [(None, False), ("", False), (TEST_REPORT_TO, True)],
    )
    def test_reporting_endpoints(
        self, rf: RequestFactory, reporting_endpoints: str, has_header: bool
    ) -> None:
        request = rf.get("/")
        with mock.patch(
            "csp.middleware.REPORTING_ENDPOINTS_HEADER", reporting_endpoints
        ):
            response: HttpResponse = self.middleware()(request)
        assert response.has_header("Report-To") is False
        assert response.has_header("Reporting-Endpoints") == has_header
