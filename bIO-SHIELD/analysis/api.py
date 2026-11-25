from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember, scoped_queryset
from analysis.services import ai_status
from compliance.models import PrivacyAssessment
from compliance.serializers import PrivacyAssessmentSerializer
from compliance.tasks import assessment_task
from documents.api import queue_task
from documents.models import HealthcareDocument
from documents.services import resolve_organization


class AssessmentViewSet(ModelViewSet):
    serializer_class = PrivacyAssessmentSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(
            PrivacyAssessment.objects.select_related("document", "organization").all(),
            self.request,
        )

    def perform_create(self, serializer):
        document = serializer.validated_data.get("document")
        organization = document.organization if document is not None else self.request.user.organization
        serializer.save(created_by=self.request.user, organization=organization)


class AIStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(ai_status())


class AssessmentGenerateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        document_id = request.data.get("document") or request.data.get("document_id")
        if not document_id:
            return Response({"detail": "document_id is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            document = HealthcareDocument.objects.get(pk=document_id)
        except (HealthcareDocument.DoesNotExist, TypeError, ValueError):
            return Response({"detail": "Document not found."}, status=status.HTTP_404_NOT_FOUND)
        organization_id = request.data.get("organization") or request.data.get("organization_id")
        try:
            organization = resolve_organization(organization_id, request.user)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        privileged = (
            getattr(request.user, "is_superuser", False) or str(getattr(request.user, "role", "")).upper() == "ADMIN"
        )
        if organization is None or (
            document.organization_id != organization.pk
            or (not privileged and organization.pk != getattr(request.user, "organization_id", None))
        ):
            return Response({"detail": "Document is outside your organization."}, status=status.HTTP_403_FORBIDDEN)
        queued = queue_task(assessment_task, document.pk, str(request.user.pk))
        return Response({"document_id": str(document.pk), "task": queued}, status=status.HTTP_202_ACCEPTED)
