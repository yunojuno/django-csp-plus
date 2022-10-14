import json

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from csp_tracker.models import ViolationReport, ViolationReportManager


@csrf_exempt
def report_uri(request: HttpRequest) -> HttpResponse:
    # {
    #     'csp-report': {
    #         'document-uri': 'http://127.0.0.1:8000/test/',
    #         'referrer': '',
    #         'violated-directive': 'img-src',
    #         'effective-directive': 'img-src',
    #         'original-policy': "default-src https:; img-src 'self'; report-uri /csp_report_tracker",
    #         'disposition': 'enforce',
    #         'blocked-uri': 'https://yunojuno-prod-assets.s3.amazonaws.com/images/static_pages/maintenance.gif',
    #         'line-number': 8,
    #         'source-file': 'http://127.0.0.1:8000/test/',
    #         'status-code': 200,
    #         'script-sample': ''
    #     }
    # }
    data = json.loads(request.body.decode())
    csp_report = data["csp-report"]
    report = ViolationReport.objects.create(
        document_uri = csp_report["document-uri"],
        violated_directive = csp_report["violated-directive"],
        effective_directive = csp_report["effective-directive"],
        original_policy = csp_report["original-policy"],
        disposition = csp_report["disposition"],
        blocked_uri = csp_report["blocked-uri"],
        status_code = csp_report["status-code"],
        script_sample = csp_report["script-sample"],
    )
    print(report)

    return HttpResponse()
