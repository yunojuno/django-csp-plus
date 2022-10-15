from __future__ import annotations

from django.db import models


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
        unique_together = ("value", "directive")

    def __str__(self) -> str:
        return f"{self.directive} {self.value}"

    @property
    def as_directive(self) -> str:
        return f"{self.directive} {self.value}"


# default rule in the absence of all others
DEFAULT_CSP = CspRule(directive=DirectiveChoices.DEFAULT_SRC, value="'self'")


class ViolationReportQuerySet(models.QuerySet):
    pass


class ViolationReportManager(models.Manager):
    def get_img_src_includes(self) -> str:
        values = (
            self.get_queryset()
            # .filter(include_in_csp=True)
            # .exclude(csp_value="")
            # .values_list("csp_value", flat=True)
            .distinct()
        )
        return " ".join(values)


class ViolationReport(models.Model):

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
    # violated_directive = models.TextField()
    effective_directive = models.TextField()
    # original_policy = models.TextField()
    disposition = models.CharField(max_length=12)
    blocked_uri = models.URLField()
    # line_number = models.PositiveBigIntegerField(blank=True, null=True)
    # source_file = models.URLField()
    # status_code = models.PositiveIntegerField()
    # script_sample = models.CharField(max_length=40)
    request_count = models.IntegerField(default=1)

    objects = ViolationReportManager.from_queryset(ViolationReportQuerySet)()

    class Meta:
        unique_together = ("effective_directive", "blocked_uri")

    def __str__(self) -> str:
        return (
            f"CSP violation: {self.effective_directive} - "
            f"{self.blocked_uri} [{self.request_count}]"
        )
