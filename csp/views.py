import json
import logging

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from .models import CspReport, CspRule, ReportData
from .policy import get_csp, get_default_rules

logger = logging.getLogger(__name__)


@csrf_exempt
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
    data = json.loads(request.body.decode())
    csp_report = data["csp-report"]
    vr = ReportData(**csp_report)
    CspReport.objects.save_report(vr)
    logger.debug(json.dumps(data, indent=2, sort_keys=True))
    return HttpResponse()


def diagnostics(request: HttpRequest) -> HttpResponse:
    default_rules = get_default_rules()
    extra_rules = list(CspRule.objects.enabled().directive_values())
    csp = get_csp()
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
