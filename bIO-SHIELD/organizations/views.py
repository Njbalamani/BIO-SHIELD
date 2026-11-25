from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from organizations.models import Organization
from organizations.services import organizations_for_user


class OrganizationListView(LoginRequiredMixin, ListView):
    model = Organization
    template_name = "organizations/list.html"
    context_object_name = "organizations"

    def get_queryset(self):
        return organizations_for_user(self.request.user)
