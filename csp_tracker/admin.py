from django.contrib import admin

from .models import ViolationReport


@admin.register(ViolationReport)
class ViolationReportAdmin(admin.ModelAdmin):
    pass
