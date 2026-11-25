from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember, scoped_queryset
from audit.models import AuditLog
from audit.serializers import AuditLogSerializer


class AuditLogViewSet(ModelViewSet):
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        queryset = AuditLog.objects.select_related("user", "organization").all()
        return scoped_queryset(queryset, self.request)
