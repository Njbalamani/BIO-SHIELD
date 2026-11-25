from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from organizations.services import organizations_for_user
from reports.models import Report


class ReportListView(LoginRequiredMixin, ListView):
    model = Report
    template_name = "reports/list.html"
    context_object_name = "reports"
    paginate_by = 25

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return Report.objects.filter(organization_id__in=organization_ids).select_related("document", "assessment")
