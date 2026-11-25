from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from audit.models import AuditLog
from organizations.services import organizations_for_user


class AuditLogListView(LoginRequiredMixin, ListView):
    model = AuditLog
    template_name = "audit/list.html"
    context_object_name = "audit_logs"
    paginate_by = 50

    def get_queryset(self):
        organization_ids = list(organizations_for_user(self.request.user).values_list("pk", flat=True))
        return AuditLog.objects.filter(organization_id__in=organization_ids).select_related("user", "organization")
