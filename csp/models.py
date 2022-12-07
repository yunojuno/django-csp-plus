from __future__ import annotations

import logging

from django.db import models
from django.db.models import F
from django.db.utils import IntegrityError
from django.utils.timezone import now as tz_now
from pydantic import BaseModel, Field

from .utils import strip_query

logger = logging.getLogger(__name__)


class ReportData(BaseModel):

    # browser support for CSP reports turns out to be patchy at best -
    # all fields are optional on the way in, but we need at least the
    # violated_directive and the blocked_uri to be able to make sense of
    # the report.

    # mandatory fields - without these we cannot process the report the
    # min_length ensures we don't have an empty string
    blocked_uri: str = Field(alias="blocked-uri", min_length=1)
    effective_directive: str = Field(alias="effective-directive", min_length=1)
    # optional fields - we don't use these currently
    disposition: str | None = Field("", alias="disposition")
    document_uri: str | None = Field("", alias="document-uri")
    original_policy: str | None = Field(alias="original-policy")
    referrer: str | None = Field(alias="referrer")
    script_sample: str | None = Field(alias="script-sample")
    status_code: str | None = Field(0, alias="status-code")
    violated_directive: str | None = Field(alias="violated-directive")

    class Config:
        allow_population_by_field_name = True


class DispositionChoices(models.TextChoices):

    ENFORCE = ("enforce", "Enforce")
    REPORT = ("report", "Report only")


class DirectiveChoices(models.TextChoices):

    DEFAULT_SRC = ("default-src", "default-src")
    CHILD_SRC = ("child-src", "child-src")
    CONNECT_SRC = ("connect-src", "connect-src")
    FONT_SRC = ("font-src", "font-src")
    FRAME_SRC = ("frame-src", "frame-src")
    IMG_SRC = ("img-src", "img-src")
    MANIFEST_SRC = ("manifest-src", "manifest-src")
    MEDIA_SRC = ("media-src", "media-src")
    OBJECT_SRC = ("object-src", "object-src")
    PREFETCH_SRC = ("prefetch-src", "prefetch-src")
    REPORT_URI = ("report-uri", "report-uri")
    SCRIPT_SRC = ("script-src", "script-src")
    SCRIPT_SRC_ELEM = ("script-src-elem", "script-src-elem")
    SCRIPT_SRC_ATTR = ("script-src-attr", "script-src-attr")
    STYLE_SRC = ("style-src", "style-src")
    STYLE_SRC_ELEM = ("style-src-elem", "style-src-elem")
    STYLE_SRC_ATTR = ("style-src-attr", "style-src-attr")
    WORKER_SRC = ("worker-src", "worker-src")


class CspRuleQuerySet(models.QuerySet):
    def enabled(self) -> CspRuleQuerySet:
        return self.filter(enabled=True)

    def directive_values(self) -> models.ValuesQuerySet:
        return self.values_list("directive", "value")


class CspRuleManager(models.Manager):
    pass


class CspRule(models.Model):

    REQUIRE_SINGLE_QUOTE = [
        "nonce",
        "none",
        "report-sample",
        "self",
        "strict-dynamic",
        "unsafe-eval",
        "unsafe-hashes",
        "unsafe-inline",
        "wasm-unsafe-eval",
    ]
    REQUIRE_TRAILING_COLON = [
        "http",
        "https",
        "wss",
        "blob",
        "data",
        "mediastream",
        "filesystem",
    ]
    # require the "unsafe-" prefix
    REQUIRE_UNSAFE_PREFIX = ["inline", "eval"]

    directive = models.CharField(max_length=50, choices=DirectiveChoices.choices)
    value = models.CharField(max_length=255)
    enabled = models.BooleanField(default=False)

    objects = CspRuleManager.from_queryset(CspRuleQuerySet)()

    class Meta:
        verbose_name = "CSP Rule"
        unique_together = ("value", "directive")
        ordering = ["directive", "value"]

    def __str__(self) -> str:
        return f"{self.directive} {self.value}"

    @classmethod
    def clean_value(cls, value: str) -> str:
        value = value.lower()
        if value in cls.REQUIRE_SINGLE_QUOTE:
            return f"'{value}'"
        if value in cls.REQUIRE_TRAILING_COLON:
            return f"{value}:"
        if value in cls.REQUIRE_UNSAFE_PREFIX:
            return f"'unsafe-{value}'"
        if source := strip_query(value):
            return source
        # not sure what we have here - let it go through
        return value


class CspReportQuerySet(models.QuerySet):
    pass


class CspReportManager(models.Manager):
    def save_report(self, data: ReportData) -> CspReport:
        report, _ = CspReport.objects.get_or_create(
            effective_directive=data.effective_directive,
            blocked_uri=data.blocked_uri[:200],
        )
        # we udpate with the latest page that has caused the violation
        report.document_uri = (data.document_uri or "")[:200]
        report.disposition = data.disposition
        report.request_count = F("request_count") + 1
        report.last_updated_at = tz_now()
        report.save()
        return report


class CspReport(models.Model):

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
    document_uri = models.URLField()
    effective_directive = models.TextField()
    disposition = models.CharField(max_length=12)
    blocked_uri = models.URLField()
    request_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=tz_now)
    last_updated_at = models.DateTimeField(default=tz_now)

    objects = CspReportManager.from_queryset(CspReportQuerySet)()

    class Meta:
        verbose_name = "CSP Violation"
        unique_together = ("effective_directive", "blocked_uri")
        ordering = ["effective_directive", "blocked_uri"]

    def __str__(self) -> str:
        return (
            f"CSP violation: {self.effective_directive} - "
            f"{self.blocked_uri} [{self.request_count}]"
        )


def convert_report(report: CspReport, enable: bool = True) -> CspRule | None:
    """Convert report to a rule and deletion the violation."""
    logger.debug("Converting violation report to new rule.")
    try:
        value = CspRule.clean_value(report.blocked_uri)
        rule = CspRule.objects.create(
            directive=report.effective_directive,
            value=value,
            enabled=enable,
        )
    except IntegrityError:
        # duplicate rule
        logger.debug("Duplicate rule found, deleting violation report.")
        report.delete()
        return None
    else:
        # once we have saved the rule, we delete the report
        logger.debug("Rule created, deleting violation report.")
        report.delete()
        return rule
