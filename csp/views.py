import json
import logging

from django.contrib.auth.decorators import user_passes_test
from django.db.utils import IntegrityError
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from pydantic import ValidationError

from .models import CspReport, CspRule, ReportData
from .policy import get_csp, get_default_rules

logger = logging.getLogger(__name__)


@csrf_exempt
@require_http_methods(["POST"])
def report_uri(request: HttpRequest) -> HttpResponse:
    # {
    #     'csp-report': {
    #         'document-uri': 'http://127.0.0.1:8000/test/',
    #         'referrer': '',
    #         'violated-directive': 'img-src',
    #         'effective-directive': 'img-src',
    #         'original-policy': "default-src https:; img-src 'self';",
    #         'disposition': 'enforce',
    #         'blocked-uri': 'https://yunojuno-prod-assets.s3.amazonaws.com/',
    #         'line-number': 8,
    #         'source-file': 'http://127.0.0.1:8000/test/',
    #         'status-code': 200,
    #         'script-sample': ''
    #     }
    # }
    request_body = request.body.decode()

    def _bad_request(msg: str) -> HttpResponseBadRequest:
        logger.debug(msg)
        logger.debug(request_body)
        return HttpResponseBadRequest(msg)

    try:
        data = json.loads(request_body)
        csp_report = data["csp-report"]
        vr = ReportData(**csp_report)
        CspReport.objects.save_report(vr)
    except json.decoder.JSONDecodeError:
        return _bad_request("Invalid CSP report - must contain valid JSON.")
    except KeyError:
        logger.exception("key error")
        return _bad_request("Invalid CSP report - must contain 'csp-report'")
    except ValidationError:
        # if the report doesn't parse, ignore it
        return _bad_request("Invalid CSP report - report data is invalid.")
    except (IntegrityError, CspReport.DoesNotExist, CspReport.MultipleObjectsReturned):
        logger.exception("Error saving CspReport")
        return HttpResponse()
    return HttpResponse(status=201)


@user_passes_test(lambda user: user.is_staff)
@require_http_methods(["GET"])
def diagnostics(request: HttpRequest) -> HttpResponse:
    default_rules = get_default_rules()
    extra_rules = list(CspRule.objects.enabled().directive_values())
    csp = get_csp(request)
    return render(
        request,
        "diagnostics.txt",
        {
            "default_rules": default_rules,
            "extra_rules": extra_rules,
            "csp": csp,
        },
        content_type="text/plain",
    )
