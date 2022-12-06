import pytest
from django.test import RequestFactory

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
    assert response.status_code == 200


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
    assert response.status_code == 200


@pytest.mark.django_db
def test_report_ui_invalid(rf: RequestFactory) -> None:
    request = rf.post(
        "/",
        data={
            "csp-report": {
                # "effective-directive": "img-src",
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
            }
        },
        content_type="application/json",
    )
    response = report_uri(request)
    assert response.status_code == 200
