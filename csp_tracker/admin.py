from django.contrib import admin
from django.http import HttpRequest

from .models import CspRule, CspRuleQuerySet, ViolationReport


@admin.register(CspRule)
class CspRuleAdmin(admin.ModelAdmin):

    list_display = ("directive", "value", "_enabled")
    actions = ["enabled_selected_rules"]

    @admin.display(boolean=True)
    def _enabled(self, obj: CspRule) -> bool:
        return obj.enabled

    @admin.action(description="Enable selected CSP rules")
    def enabled_selected_rules(
        self, request: HttpRequest, queryset: CspRuleQuerySet
    ) -> None:
        queryset.update(enabled=True)
        self.message_user(request, "Enabled rules.")


@admin.register(ViolationReport)
class ViolationReportAdmin(admin.ModelAdmin):
    list_display = ("effective_directive", "blocked_uri", "request_count")
    readonly_fields = (
        "document_uri",
        "effective_directive",
        "disposition",
        "blocked_uri",
    )
    list_filter = ("effective_directive",)
