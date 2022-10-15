from typing import Callable

from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse

from .csp import build_csp


class CSPMiddleware:
    def __init__(self, get_response: Callable) -> None:
        if not getattr(settings, "CSP_TRACKER_ENABLED", False):
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        response = self.get_response(request)
        response.headers["Content-Security-Policy"] = build_csp()
        return response
