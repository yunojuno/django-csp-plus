import json
import logging
import random
from typing import Callable, TypeAlias

from django.contrib.auth.decorators import user_passes_test
from django.db.utils import IntegrityError
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from pydantic import ValidationError

from .blacklist import is_blacklisted
from .models import CspReport, CspRule, ReportData
from .policy import get_csp, get_default_rules
from .settings import CSP_REPORT_THROTTLING

logger = logging.getLogger(__name__)

SimpleViewType: TypeAlias = Callable[[HttpRequest], HttpResponse]


def throttle_view(func: SimpleViewType) -> SimpleViewType:
    def wrapper(request: HttpRequest) -> HttpResponse:
        # CSP_REPORT_THROTTLING is a float 0..1 - if we're below the value,
        # then respond immediately without attempting to process the
        # payload.
        if random.random() < CSP_REPORT_THROTTLING:  # noqa: S311
            return HttpResponse()
        return func(request)

    return wrapper


def _validation_error(ex: ValidationError) -> str:
    """
    Parse Pydantic error into output message.

    This message goes back to the requestor, so we don't want the
    full Pydantic error - just the list of invalid fields.

    See https://docs.pydantic.dev/usage/models/#error-handling

    """
    try:
        return ", ".join([str(e["loc"][0]) for e in ex.errors()])
    except (IndexError, KeyError):
        logger.exception("Unparseable Pydantic error: %s", ex.json())
        return "unknown error"


@csrf_exempt
@require_http_methods(["POST"])
@throttle_view
def report_uri(request: HttpRequest) -> HttpResponse:
    # {
    #     'csp-report': {
    #         'document-uri': 'http://127.0.0.1:8000/test/',
    #         'referrer': '',
    #         'violated-directive': 'img-src',
    #         'effective-directive': 'img-src',
    #         'original-policy': "default-src https:; img-src 'self';",
    #         'disposition': 'enforce',
    #         'blocked-uri': 'https://example.com',
    #         'line-number': 8,
    #         'source-file': 'http://127.0.0.1:8000/test/',
    #         'status-code': 200,
    #         'script-sample': ''
    #     }
    # }
    request_body = request.body.decode()
    user_agent = request.headers.get("User-Agent", "missing User-Agent")

    def _bad_request(msg: str) -> HttpResponseBadRequest:
        logger.debug(msg)
        logger.debug("CSP reporting User-Agent: %s", user_agent)
        logger.debug("CSP report payload:\n%s", request_body)
        return HttpResponseBadRequest(msg)

    try:
        data = json.loads(request_body)
        report = ReportData(**data["csp-report"])
        if is_blacklisted(report):
            logger.debug("Ignoring blacklisted CSP report")
            return HttpResponse()
        CspReport.objects.save_report(report)
    except json.decoder.JSONDecodeError:
        return _bad_request("Invalid CSP report - must contain valid JSON.")
    except KeyError:
        return _bad_request("Invalid CSP report - must contain 'csp-report'")
    except ValidationError as ex:
        return _bad_request(
            f"Invalid CSP report - report data is invalid: {_validation_error(ex)}"
        )
    except (IntegrityError, CspReport.DoesNotExist, CspReport.MultipleObjectsReturned):
        logger.exception("Error saving CspReport")
        return HttpResponse()
    return HttpResponse(status=201, content_type="application/json")


@user_passes_test(lambda user: user.is_staff)
@require_http_methods(["GET"])
def csp_diagnostics(request: HttpRequest) -> HttpResponse:
    default_rules = get_default_rules()
    extra_rules = list(CspRule.objects.enabled().directive_values())
    csp = get_csp(request, True)
    return render(
        request,
        "csp/diagnostics.txt",
        {
            "default_rules": default_rules,
            "extra_rules": extra_rules,
            "csp": csp,
        },
        content_type="text/plain",
    )
