import base64
import logging
import os
from functools import partial
from typing import Callable

from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse
from django.urls import reverse
from django.utils.functional import SimpleLazyObject

from .policy import get_csp
from .settings import CSP_ENABLED, apply_csp_header, get_response_header

logger = logging.getLogger(__name__)


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
        self.response_header = get_response_header()
        self.context = {"report_uri": reverse("csp:report_uri")}
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse | None:
        response: HttpResponse = self.get_response(request)
        if apply_csp_header(request, response):
            self.extract_nonce(request)
            self.set_response_header(response)
        return response

    def extract_nonce(self, request: HttpRequest) -> None:
        if nonce := getattr(request, "csp_nonce", ""):
            self.context["nonce"] = f"'nonce-{nonce}'"

    def set_response_header(self, response: HttpResponse) -> None:
        try:
            # context contains report-uri and nonce
            csp = get_csp().format(**self.context)
        except KeyError:
            logger.exception("Error setting CSP response header.")
        else:
            response.headers[self.response_header] = csp
