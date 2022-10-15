from django.contrib import admin
from django.http import HttpRequest

from .models import CspRule, CspRuleQuerySet, ViolationReport, ViolationReportQuerySet


@admin.register(CspRule)
class CspRuleAdmin(admin.ModelAdmin):

    list_display = ("directive", "value", "_enabled")
    actions = ["enable_selected_rules", "disable_selected_rules"]

    @admin.display(boolean=True)
    def _enabled(self, obj: CspRule) -> bool:
        return obj.enabled

    @admin.action(description="Enable selected CSP rules")
    def enable_selected_rules(
        self, request: HttpRequest, queryset: CspRuleQuerySet
    ) -> None:
        count = queryset.update(enabled=True)
        self.message_user(request, f"Enabled {count} rules.")

    @admin.action(description="Disable selected CSP rules")
    def disable_selected_rules(
        self, request: HttpRequest, queryset: CspRuleQuerySet
    ) -> None:
        count = queryset.update(enabled=False)
        self.message_user(request, f"Disabled {count} rules.")


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
    actions = ("add_rule",)

    @admin.action(description="Add new CSP rule for selected violations.")
    def add_rule(self, request: HttpRequest, queryset: ViolationReportQuerySet) -> None:
        for report in queryset:
            CspRule.objects.create(
                directive=report.effective_directive,
                value=report.blocked_uri,
                enabled=True,
            )
        self.message_user(request, "Created new rules.")
