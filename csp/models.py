from __future__ import annotations

import logging
from collections import defaultdict
from typing import TypeAlias

from django.db import models
from django.db.models import F
from django.db.utils import IntegrityError
from django.utils.timezone import now as tz_now
from pydantic import BaseModel, Field, root_validator, validator

from .settings import PolicyType
from .utils import strip_query

logger = logging.getLogger(__name__)

PydanticValues: TypeAlias = dict[str, str | None]


class ReportData(BaseModel):

    # browser support for CSP reports turns out to be patchy at best -
    # all fields are optional on the way in, but we need at least the
    # violated_directive and the blocked_uri to be able to make sense of
    # the report.

    # mandatory fields - without these we cannot process the report the
    # min_length ensures we don't have an empty string
    blocked_uri: str = Field(alias="blocked-uri", min_length=1)
    # we must have one of these - validate_directives enforces this
    effective_directive: str | None = Field(alias="effective-directive")
    violated_directive: str | None = Field(alias="violated-directive")
    # optional
    disposition: str | None = Field("", alias="disposition")
    document_uri: str | None = Field("", alias="document-uri")
    original_policy: str | None = Field(alias="original-policy")
    referrer: str | None = Field(alias="referrer")
    script_sample: str | None = Field(alias="script-sample")
    status_code: str | None = Field(0, alias="status-code")

    @validator("document_uri", "blocked_uri")
    def strip_uri(cls, uri: str) -> str:
        """
        Strip querystring and truncate to fit model length.

        We don't care about querystring params (CSP doesn't), and we can't
        store URLs > 200 chars long, so we truncate here.

        """
        return strip_query(uri)[:200] if uri else ""

    @root_validator
    def validate_directives(cls, values: PydanticValues) -> PydanticValues:
        """Ensure that we have either effective_directive or violated_directive."""
        if values.get("effective_directive", ""):
            return values
        # if effective_directive is empty, but violated_directive is not,
        # then udpate the former with the latter.
        if violated_directive := values.get("violated_directive", ""):
            logger.debug(
                "'effective_directive' missing - using 'violated_directive' attr."
            )
            values["effective_directive"] = violated_directive
            return values
        raise ValueError(
            "Either 'effective_directive' or 'violated_directive' must be present."
        )

    class Config:
        allow_population_by_field_name = True


class DispositionChoices(models.TextChoices):

    ENFORCE = ("enforce", "Enforce")
    REPORT = ("report", "Report only")


class DirectiveChoices(models.TextChoices):

    BASE_URI = ("base-uri", "base-uri")
    CHILD_SRC = ("child-src", "child-src")
    CONNECT_SRC = ("connect-src", "connect-src")
    DEFAULT_SRC = ("default-src", "default-src")
    FONT_SRC = ("font-src", "font-src")
    FORM_ACTION = ("form-action", "form-action")
    FRAME_ANCESTORS = ("frame-ancestors", "frame-ancestors")
    FRAME_SRC = ("frame-src", "frame-src")
    IMG_SRC = ("img-src", "img-src")
    MANIFEST_SRC = ("manifest-src", "manifest-src")
    MEDIA_SRC = ("media-src", "media-src")
    OBJECT_SRC = ("object-src", "object-src")
    PREFETCH_SRC = ("prefetch-src", "prefetch-src [DEPRECATED]")
    REPORT_TO = ("report-to", "report-to")
    REPORT_URI = ("report-uri", "report-uri")
    SCRIPT_SRC = ("script-src", "script-src")
    SCRIPT_SRC_ATTR = ("script-src-attr", "script-src-attr")
    SCRIPT_SRC_ELEM = ("script-src-elem", "script-src-elem")
    STYLE_SRC = ("style-src", "style-src")
    STYLE_SRC_ATTR = ("style-src-attr", "style-src-attr")
    STYLE_SRC_ELEM = ("style-src-elem", "style-src-elem")
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
    def save_report(self, data: ReportData) -> CspReport | None:
        report, _ = CspReport.objects.get_or_create(
            effective_directive=data.effective_directive,
            blocked_uri=data.blocked_uri,
        )
        # we udpate with the latest page that has caused the violation
        report.document_uri = data.document_uri
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
    #         'blocked-uri': 'https://example.com',
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


class CspReportBlacklistQueryset(models.QuerySet):
    def as_dict(self) -> PolicyType:
        values = defaultdict(list)
        for directive, blocked_uri in self.values_list("directive", "blocked_uri"):
            values[directive].append(blocked_uri)
        return values


class CspReportBlacklist(models.Model):
    """
    Combination of directive + domain to ignore.

    CSP reports are flakey, to say the least, and some directive/domain
    combos get stuck. This model creates a blacklist that is used to
    stop logging reports once you are sure you have the rules set up.

    """

    directive = models.CharField(max_length=50, choices=DirectiveChoices.choices)
    blocked_uri = models.URLField()

    objects = CspReportBlacklistQueryset().as_manager()

    class Meta:
        verbose_name_plural = verbose_name = "CSP Blacklist"
        unique_together = ("directive", "blocked_uri")
        ordering = ["directive", "blocked_uri"]

    def __str__(self) -> str:
        return f"{self.directive} {self.blocked_uri}"
