from unittest import mock

import pytest
from django.db.utils import IntegrityError
from django.test import RequestFactory

from csp.models import CspReport, CspReportManager
from csp.views import report_uri


@pytest.mark.django_db
def test_report_ui(rf: RequestFactory) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                "document-uri": "http://127.0.0.1:8000/test/",
                "referrer": "",
                "violated-directive": "img-src",
                "effective-directive": "img-src",
                "original-policy": "default-src https:; img-src 'self';",
                "disposition": "enforce",
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
                "line-number": 8,
                "source-file": "http://127.0.0.1:8000/test/",
                "status-code": 200,
                "script-sample": "",
            }
        },
        content_type="application/json",
    )
    response = report_uri(request)
    assert response.status_code == 201


@pytest.mark.django_db
def test_report_ui_minimal(rf: RequestFactory) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                "effective-directive": "img-src",
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
            }
        },
        content_type="application/json",
    )
    response = report_uri(request)
    assert response.status_code == 201


@pytest.mark.django_db
def test_report_ui_invalid(rf: RequestFactory) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
            }
        },
        content_type="application/json",
    )
    response = report_uri(request)
    assert response.status_code == 400


@pytest.mark.django_db
def test_report_ui_deprecated_attr(rf: RequestFactory) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                "violated-directive": "img-src",
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
            }
        },
        content_type="application/json",
    )
    response = report_uri(request)
    assert response.status_code == 201


@pytest.mark.django_db
@pytest.mark.parametrize(
    "error", [IntegrityError, CspReport.DoesNotExist, CspReport.MultipleObjectsReturned]
)
def test_report_ui_error_on_save(rf: RequestFactory, error: type[Exception]) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                "effective-directive": "",
                "blocked-uri": "",
            }
        },
        content_type="application/json",
    )
    with mock.patch.object(CspReportManager, "save_report") as mock_save:
        mock_save.side_effect = error
        response = report_uri(request)
    assert response.status_code == 400
