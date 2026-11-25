from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from compliance.models import ComplianceChecklist
from organizations.services import organizations_for_user


class ChecklistListView(LoginRequiredMixin, ListView):
    model = ComplianceChecklist
    template_name = "compliance/list.html"
    context_object_name = "checklists"
    paginate_by = 25

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return ComplianceChecklist.objects.filter(organization_id__in=organization_ids).select_related("assessment")
