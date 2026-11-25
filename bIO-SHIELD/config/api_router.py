from django.urls import include, path
from rest_framework.routers import DefaultRouter

from accounts.api import LoginAPIView, LogoutAPIView, MeAPIView, RegisterAPIView
from analysis.api import AIStatusView, AssessmentGenerateView, AssessmentViewSet
from audit.api import AuditLogViewSet
from compliance.api import ChecklistViewSet
from dashboard.api import DashboardMetricsView
from documents.api import (
    AccessAlertViewSet,
    AccessEventViewSet,
    AnonymizationJobViewSet,
    DocumentVersionViewSet,
    DocumentViewSet,
    FindingViewSet,
)
from organizations.api import OrganizationViewSet
from reports.api import ReportGenerateView, ReportViewSet

router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organizations")
router.register("documents", DocumentViewSet, basename="documents")
router.register("document-versions", DocumentVersionViewSet, basename="document-versions")
router.register("findings", FindingViewSet, basename="findings")
router.register("assessments", AssessmentViewSet, basename="assessments")
router.register("anonymization-jobs", AnonymizationJobViewSet, basename="anonymization-jobs")
router.register("access-events", AccessEventViewSet, basename="access-events")
router.register("alerts", AccessAlertViewSet, basename="alerts")
router.register("checklists", ChecklistViewSet, basename="checklists")
router.register("reports", ReportViewSet, basename="reports")
router.register("audit-logs", AuditLogViewSet, basename="audit-logs")

urlpatterns = [
    path("auth/register/", RegisterAPIView.as_view(), name="auth-register"),
    path("auth/login/", LoginAPIView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutAPIView.as_view(), name="auth-logout"),
    path("auth/me/", MeAPIView.as_view(), name="auth-me"),
    path("dashboard/metrics/", DashboardMetricsView.as_view(), name="dashboard-metrics"),
    path("ai/status/", AIStatusView.as_view(), name="ai-status"),
    path("reports/generate/", ReportGenerateView.as_view(), name="reports-generate"),
    path("assessments/generate/", AssessmentGenerateView.as_view(), name="assessments-generate"),
    path("", include(router.urls)),
]
