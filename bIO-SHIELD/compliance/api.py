from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember, scoped_queryset
from compliance.models import ComplianceChecklist
from compliance.serializers import ComplianceChecklistSerializer
from documents.services import resolve_organization


class ChecklistViewSet(ModelViewSet):
    serializer_class = ComplianceChecklistSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(
            ComplianceChecklist.objects.select_related("organization", "assessment").all(),
            self.request,
        )

    def perform_create(self, serializer):
        organization_id = self.request.data.get("organization") or self.request.data.get("organization_id")
        organization = resolve_organization(organization_id, self.request.user)
        if organization is None:
            organization = self.request.user.organization
        serializer.save(created_by=self.request.user, organization=organization, score=0)
