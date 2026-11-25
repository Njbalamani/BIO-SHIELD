import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.views.generic import TemplateView

from dashboard.services import get_dashboard_metrics
from documents.models import HealthcareDocument
from organizations.services import organizations_for_user


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        metrics = get_dashboard_metrics(self.request.user)
        context["metrics"] = metrics
        context["metrics_json"] = json.dumps(metrics, sort_keys=True)
        context["documents_count"] = metrics["documents_total"]
        context["findings_count"] = metrics["findings_total"]
        context["recent_documents"] = (
            HealthcareDocument.objects.filter(organization__in=organizations_for_user(self.request.user))
            .annotate(finding_count=Count("findings"))
            .select_related("organization")[:5]
        )
        return context
