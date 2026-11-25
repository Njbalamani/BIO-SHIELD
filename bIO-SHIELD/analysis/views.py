from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from compliance.models import PrivacyAssessment
from organizations.services import organizations_for_user


class AssessmentListView(LoginRequiredMixin, ListView):
    model = PrivacyAssessment
    template_name = "assessments/list.html"
    context_object_name = "assessments"
    paginate_by = 25

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return PrivacyAssessment.objects.filter(organization_id__in=organization_ids).select_related("document")
