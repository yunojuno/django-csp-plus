from django.contrib import admin

from .models import ViolationReport


@admin.register(ViolationReport)
class ViolationReportAdmin(admin.ModelAdmin):
    readonly_fields = (
        "document_uri",
        "violated_directive",
        "effective_directive",
        "original_policy",
        "disposition",
        "blocked_uri",
        "line_number",
        "source_file",
        "status_code",
        "script_sample",
    )
