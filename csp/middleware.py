import base64
import logging
import os
import random
from functools import partial
from typing import Callable

from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse
from django.utils.functional import SimpleLazyObject

from .policy import get_csp
from .settings import (
    CSP_ENABLED,
    CSP_REPORT_SAMPLING,
    CSP_RESPONSE_HEADER,
    process_request,
    process_response,
)

logger = logging.getLogger(__name__)


def add_report_uri() -> bool:
    """Return True if we should add the report-uri directive."""
    return random.random() <= CSP_REPORT_SAMPLING  # noqa: S311


class CspNonceMiddleware:
    """Add the csp_nonce to all HttpResponses."""

    def __init__(self, get_response: Callable) -> None:
        if not CSP_ENABLED:
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        # direct lift from mozilla/django-csp (h/t)
        nonce = partial(self._make_nonce, request)
        request.csp_nonce = SimpleLazyObject(nonce)
        response = self.get_response(request)
        return response

    def _make_nonce(self, request: HttpRequest) -> str:
        if not getattr(request, "_csp_nonce", None):
            request._csp_nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        return request._csp_nonce


class CspHeaderMiddleware:
    """Set the CSP header on the response."""

    def __init__(self, get_response: Callable) -> None:
        if not CSP_ENABLED:
            raise MiddlewareNotUsed("Disabling CSPMiddleware")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        response: HttpResponse = self.get_response(request)
        if process_request(request) and process_response(response):
            response.headers[CSP_RESPONSE_HEADER] = get_csp(request, add_report_uri())
        return response
