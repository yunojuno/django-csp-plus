from django.urls import path

from .views import diagnostics, report_uri

app_name = "csp"

urlpatterns = [
    path("report-uri/", report_uri, name="report_uri"),
    path("diagnostics/", diagnostics, name="diagnostics"),
]
