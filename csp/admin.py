from django.contrib import admin
from django.db.utils import IntegrityError
from django.http import HttpRequest

from .models import (
    CspReport,
    CspReportBlacklist,
    CspReportQuerySet,
    CspRule,
    CspRuleQuerySet,
    convert_report,
)
from .utils import strip_path


@admin.register(CspRule)
class CspRuleAdmin(admin.ModelAdmin):

    list_display = ("directive", "value", "_enabled")
    list_filter = ("directive", "enabled")
    actions = [
        "enable_selected_rules",
        "disable_selected_rules",
        "strip_selected_rules",
    ]

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

    @admin.action(description="Strip path from selected CSP rules")
    def strip_selected_rules(
        self, request: HttpRequest, queryset: CspReportQuerySet
    ) -> None:
        """Strip paths off selected rules."""
        stripped = 0
        ignored = 0
        deleted = 0
        for rule in queryset:
            stripped_value = strip_path(rule.value)
            if stripped_value == rule.value:
                ignored += 1
            else:
                rule.value = stripped_value
                try:
                    rule.save(update_fields=["value"])
                except IntegrityError:
                    # we have a duplicate rule - because we are
                    # stripping off the path multiple rules may now
                    # clash (same origin), and so we delete the
                    # duplicates.
                    rule.delete()
                    deleted += 1
                else:
                    stripped += 1
        if stripped:
            self.message_user(
                request, f"Successfully stripped {stripped} rules.", "success"
            )
        if ignored:
            self.message_user(request, f"Ignored {ignored} unchanged rules.", "success")
        if deleted:
            self.message_user(request, f"Deleted {deleted} duplicate rules.", "error")


@admin.register(CspReport)
class CspReportAdmin(admin.ModelAdmin):
    list_display = (
        "effective_directive",
        "blocked_uri",
        "request_count",
        "last_updated_at",
    )
    readonly_fields = (
        "document_uri",
        "effective_directive",
        "disposition",
        "blocked_uri",
        "created_at",
        "last_updated_at",
        "request_count",
    )
    list_filter = ("effective_directive", "last_updated_at")
    actions = ("add_rule", "add_to_blacklist")

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

    @admin.action(description="Blacklist selected violations.")
    def add_to_blacklist(
        self, request: HttpRequest, queryset: CspReportQuerySet
    ) -> None:
        blacklisted = 0
        duplicates = 0
        for report in queryset:
            obj, created = CspReportBlacklist.objects.get_or_create(
                directive=report.effective_directive, blocked_uri=report.blocked_uri
            )
            report.delete()
            if created:
                blacklisted += 1
            else:
                duplicates += 1
        if blacklisted:
            self.message_user(request, f"Blacklisted {blacklisted} reports.", "success")
        if duplicates:
            self.message_user(request, f"Ignored {duplicates} duplicates.", "warning")


@admin.register(CspReportBlacklist)
class CspReportBlacklistAdmin(admin.ModelAdmin):
    list_display = (
        "directive",
        "blocked_uri",
    )
    list_filter = ("directive",)
