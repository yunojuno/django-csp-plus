from django.db import models


class ViolationReportQuerySet(models.QuerySet):
    pass


class ViolationReportManager(models.Manager):
    pass


class ViolationReport(models.Model):

    blocked_uri = models.URLField()
    disposition = models.CharField(max_length=12)
    effective_directive = models.TextField()
    original_policy = models.TextField()
    violated_directive = models.TextField()
    script_sample = models.CharField(max_length=40)
    status_code = models.PositiveIntegerField()

    objects = ViolationReportManager.from_queryset(ViolationReportQuerySet)()
