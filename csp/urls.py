from django.urls import path

from .views import report_uri

app_name = "csp"

urlpatterns = [
    path("csp-report-uri/", report_uri, name="csp_report_uri"),
]
