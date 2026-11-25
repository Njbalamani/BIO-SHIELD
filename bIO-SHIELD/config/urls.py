from django.contrib import admin
from django.urls import include, path

from config.health import live, ready
from dashboard.views import DashboardView
from documents import urls as document_urls

urlpatterns = [
    path("health/", live, name="health"),
    path("health/live/", live, name="health-live"),
    path("health/ready/", ready, name="health-ready"),
    path("healthz/", live, name="healthz"),
    path("api/", include("config.api_router")),
    path("admin/", admin.site.urls),
    path("", DashboardView.as_view(), name="home"),
    path("dashboard/", include("dashboard.urls", namespace="dashboard")),
    path("documents/", include("documents.urls", namespace="documents")),
    path("findings/", include((document_urls.finding_urlpatterns, "findings"), namespace="findings")),
    path(
        "assessments/",
        include((document_urls.assessment_urlpatterns, "assessments"), namespace="assessments"),
    ),
    path(
        "anonymization/",
        include((document_urls.anonymization_urlpatterns, "anonymization"), namespace="anonymization"),
    ),
    path("access/", include((document_urls.access_urlpatterns, "access"), namespace="access")),
    path("compliance/", include("compliance.urls", namespace="compliance")),
    path("reports/", include("reports.urls", namespace="reports")),
    path("accounts/", include("accounts.urls", namespace="accounts")),
    path("organizations/", include("organizations.urls", namespace="organizations")),
    path("audit/", include("audit.urls", namespace="audit")),
]
