from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from django.urls import reverse

from csp_tracker.models import ViolationReport


class CSPMiddleware:
    def __init__(self, get_response):
        if not getattr(settings, "CSP_TRACKER_ENABLED", False):
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)
        report_uri = reverse("csp_report_uri")
        img_src_includes = ViolationReport.objects.get_img_src_includes()
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"img-src 'self' {img_src_includes}; "
            f"report-uri {report_uri} "
        )
        return response
