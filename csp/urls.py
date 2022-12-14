from django.urls import path

from .views import csp_diagnostics, report_uri

app_name = "csp"

urlpatterns = [
    path("report-uri/", report_uri, name="report_uri"),
    path("diagnostics/", csp_diagnostics, name="csp_diagnostics"),
]
