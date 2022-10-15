from __future__ import annotations

from django.db import models
from django.utils.timezone import now as tz_now
from pydantic import BaseModel, Field


class CspReportx(BaseModel):

    blocked_uri: str = Field(alias="blocked-uri")
    disposition: str = Field(alias="disposition")
    document_uri: str = Field(alias="document-uri")
    effective_directive: str = Field(alias="effective-directive")
    original_policy: str = Field(alias="original-policy")
    referrer: str = Field(alias="referrer")
    script_sample: str = Field(alias="script-sample")
    status_code: str = Field(alias="status-code")
    violated_directive: str = Field(alias="violated-directive")

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


class CspRuleManager(models.Manager):
    def get_directive_values(self, directive: str) -> str:
        return " ".join(
            self.get_queryset()
            .filter(enabled=True)
            .filter(directive=directive)
            .values_list("value", flat=True)
        )

    def get_directive(self, directive: str) -> str:
        values = self.get_directive_values(directive)
        return f"{directive} {values};"


class CspRule(models.Model):
    directive = models.CharField(max_length=50, choices=DirectiveChoices.choices)
    value = models.CharField(max_length=255)
    enabled = models.BooleanField(default=False)

    objects = CspRuleManager.from_queryset(CspRuleQuerySet)()

    class Meta:
        verbose_name = "CSP Rule"
        unique_together = ("value", "directive")

    def __str__(self) -> str:
        return f"{self.directive} {self.value}"

    @property
    def as_directive(self) -> str:
        return f"{self.directive} {self.value}"

    @classmethod
    def default_directives(self) -> dict[str, str]:
        return {d: "self" for d in DirectiveChoices.names}


# default rule in the absence of all others
DEFAULT_CSP = CspRule(directive=DirectiveChoices.DEFAULT_SRC, value="'self'")


class CspReportQuerySet(models.QuerySet):
    pass


class CspReportManager(models.Manager):
    def save_report(self, payload: CspReportx) -> CspReport:
        report, _ = CspReport.objects.get_or_create(
            effective_directive=payload.effective_directive,
            blocked_uri=payload.blocked_uri,
        )
        report.request_count += 1
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

    def __str__(self) -> str:
        return (
            f"CSP violation: {self.effective_directive} - "
            f"{self.blocked_uri} [{self.request_count}]"
        )
