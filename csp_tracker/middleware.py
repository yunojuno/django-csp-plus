from typing import Callable

from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse

from .csp import get_csp
from .settings import CSP_ENABLED


class CSPMiddleware:
    def __init__(self, get_response: Callable) -> None:
        if not CSP_ENABLED:
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        response = self.get_response(request)
        response.headers["Content-Security-Policy"] = get_csp()
        return response
