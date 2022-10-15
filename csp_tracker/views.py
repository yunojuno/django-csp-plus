import json
import logging

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from csp_tracker.models import CspReport, CspReportx

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
    vr = CspReportx(**csp_report)
    CspReport.objects.save_report(vr)
    logger.debug(json.dumps(data, indent=2, sort_keys=True))
    return HttpResponse()
