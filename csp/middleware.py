import base64
import os
from functools import partial
from typing import Callable

from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse
from django.utils.functional import SimpleLazyObject

from .policy import get_csp
from .settings import CSP_ENABLED, get_response_header


class CSPMiddleware:
    def __init__(self, get_response: Callable) -> None:
        if not CSP_ENABLED:
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        # direct lift from mozilla/django-csp (h/t)
        nonce = partial(self._make_nonce, request)
        request.csp_nonce = SimpleLazyObject(nonce)
        response = self.get_response(request)
        self.set_csp(request, response)
        return response

    def _make_nonce(self, request: HttpRequest) -> str:
        if not getattr(request, "_csp_nonce", None):
            request._csp_nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        return request._csp_nonce

    def set_csp(self, request: HttpRequest, response: HttpResponse) -> None:
        """Set CSP header on response object."""
        csp_header = get_csp().format(csp_nonce=request.csp_nonce)
        response.headers[get_response_header()] = csp_header
