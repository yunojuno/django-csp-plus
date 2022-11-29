from django.contrib import admin
from django.urls import path
from django.views import debug
from django.views.generic import TemplateView

from csp.views import report_uri

admin.autodiscover()

urlpatterns = [
    path("", debug.default_urlconf),
    path("admin/", admin.site.urls),
    path(
        "test/",
        TemplateView.as_view(template_name="violation.html"),
    ),
    path("csp_report_tracker", report_uri, name="csp_report_uri"),
]
