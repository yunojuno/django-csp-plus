import json
import logging

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from csp_tracker.models import ViolationReport

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
    report, created = ViolationReport.objects.get_or_create(
        # document_uri = csp_report["document-uri"],
        # violated_directive = csp_report["violated-directive"],
        effective_directive=csp_report["effective-directive"],
        # original_policy = csp_report["original-policy"],
        # disposition = csp_report["disposition"],
        blocked_uri=csp_report["blocked-uri"],
        # status_code = csp_report["status-code"],
        # script_sample = csp_report["script-sample"],
    )
    if created:
        # NB this is not thread-safe - but it's not significant - the
        # absolute number isn't critical
        report.request_count += 1
        report.save()
    logger.debug(json.dumps(data, indent=2, sort_keys=True))
    return HttpResponse()
