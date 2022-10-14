from django.db import models


class ViolationReportQuerySet(models.QuerySet):
    pass


class ViolationReportManager(models.Manager):
    pass


class ViolationReport(models.Model):

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

    document_uri = models.URLField()
    referrer = models.URLField(blank=True)
    violated_directive = models.TextField()
    effective_directive = models.TextField()
    original_policy = models.TextField()
    disposition = models.CharField(max_length=12)
    blocked_uri = models.URLField()
    line_number = models.PositiveBigIntegerField(blank=True, null=True)
    source_file = models.URLField()
    status_code = models.PositiveIntegerField()
    script_sample = models.CharField(max_length=40)

    objects = ViolationReportManager.from_queryset(ViolationReportQuerySet)()
