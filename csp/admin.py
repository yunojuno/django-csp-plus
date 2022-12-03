from django.contrib import admin
from django.http import HttpRequest

from .models import (
    CspReport,
    CspReportQuerySet,
    CspRule,
    CspRuleQuerySet,
    convert_report,
)


@admin.register(CspRule)
class CspRuleAdmin(admin.ModelAdmin):

    list_display = ("directive", "value", "_enabled")
    actions = ["enable_selected_rules", "disable_selected_rules"]

    @admin.display(boolean=True)
    def _enabled(self, obj: CspRule) -> bool:
        return obj.enabled

    def clear_cache(self) -> None:
        from .policy import clear_cache as clear_csp_cache

        clear_csp_cache()

    @admin.action(description="Enable selected CSP rules")
    def enable_selected_rules(
        self, request: HttpRequest, queryset: CspRuleQuerySet
    ) -> None:
        count = queryset.update(enabled=True)
        self.clear_cache()
        self.message_user(request, f"Enabled {count} rules.")

    @admin.action(description="Disable selected CSP rules")
    def disable_selected_rules(
        self, request: HttpRequest, queryset: CspRuleQuerySet
    ) -> None:
        count = queryset.update(enabled=False)
        self.clear_cache()
        self.message_user(request, f"Disabled {count} rules.")


@admin.register(CspReport)
class CspReportAdmin(admin.ModelAdmin):
    list_display = ("effective_directive", "blocked_uri", "request_count")
    readonly_fields = (
        "document_uri",
        "effective_directive",
        "disposition",
        "blocked_uri",
        "created_at",
        "last_updated_at",
        "request_count",
    )
    list_filter = ("effective_directive",)
    actions = ("add_rule",)

    @admin.action(description="Add new CSP rule for selected violations.")
    def add_rule(self, request: HttpRequest, queryset: CspReportQuerySet) -> None:
        created: list[CspRule] = []
        duplicates = 0
        for report in queryset:
            if rule := convert_report(report, enable=True):
                created.append(rule)
            else:
                duplicates += 1
        if created:
            self.message_user(request, f"Created {len(created)} new rules.", "success")
        if duplicates:
            self.message_user(request, f"Ignored {duplicates} duplicates.", "warning")
