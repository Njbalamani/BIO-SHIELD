from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember, scoped_queryset
from documents.api import _download_response, queue_task
from documents.services import record_access_event, resolve_organization
from reports.models import Report
from reports.serializers import ReportSerializer
from reports.services import build_report_summary
from reports.tasks import pdf_report_task


class ReportViewSet(ModelViewSet):
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(
            Report.objects.select_related("organization", "document", "assessment").all(),
            self.request,
        )

    def perform_create(self, serializer):
        document = serializer.validated_data.get("document")
        organization = document.organization if document is not None else self.request.user.organization
        serializer.save(created_by=self.request.user, organization=organization)

    def destroy(self, request, *args, **kwargs):
        raise PermissionDenied("Reports are retained for audit purposes.")

    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, pk=None):
        report = self.get_object()
        if report.document is not None:
            record_access_event(
                report.document,
                user=request.user,
                action="DOWNLOAD",
                request=request,
                actor_label="",
            )
        return _download_response(report, "file", f"report-{report.pk}")


class ReportGenerateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        organization_id = request.data.get("organization") or request.data.get("organization_id")
        try:
            organization = resolve_organization(organization_id, request.user)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        if organization is None:
            return Response({"detail": "No organization is available."}, status=status.HTTP_400_BAD_REQUEST)
        document_id = request.data.get("document") or request.data.get("document_id")
        assessment_id = request.data.get("assessment") or request.data.get("assessment_id")
        from compliance.models import PrivacyAssessment
        from documents.models import HealthcareDocument

        document = None
        assessment = None
        if document_id:
            document = HealthcareDocument.objects.filter(pk=document_id, organization=organization).first()
            if document is None:
                return Response({"detail": "Document not found."}, status=status.HTTP_404_NOT_FOUND)
        if assessment_id:
            assessment = PrivacyAssessment.objects.filter(pk=assessment_id, organization=organization).first()
            if assessment is None:
                return Response({"detail": "Assessment not found."}, status=status.HTTP_404_NOT_FOUND)
        title = str(request.data.get("title") or "")[:255]
        report = Report.objects.create(
            organization=organization,
            document=document,
            assessment=assessment,
            created_by=request.user,
            report_type="PRIVACY_ASSESSMENT",
            format=Report.Format.PDF,
            title=title or "BioShield Privacy Assessment Report",
            summary=build_report_summary(organization, document=document, assessment=assessment),
        )
        queued = queue_task(pdf_report_task, str(report.pk))
        return Response({"report_id": str(report.pk), "task": queued}, status=status.HTTP_202_ACCEPTED)
