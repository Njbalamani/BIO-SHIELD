from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember
from organizations.serializers import OrganizationSerializer
from organizations.services import organizations_for_user


class OrganizationViewSet(ModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return organizations_for_user(self.request.user)

    def create(self, request, *args, **kwargs):
        if not (
            getattr(request.user, "is_superuser", False) or str(getattr(request.user, "role", "")).upper() == "ADMIN"
        ):
            raise PermissionDenied("Only administrators may create organizations.")
        return super().create(request, *args, **kwargs)
