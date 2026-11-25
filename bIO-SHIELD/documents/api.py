from django.conf import settings
from django.http import FileResponse, HttpResponse
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from accounts.api import IsOrganizationMember, scoped_queryset
from analysis.services import review_finding
from documents.models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)
from documents.serializers import (
    AccessAlertSerializer,
    AccessEventSerializer,
    AnonymizationJobSerializer,
    DocumentVersionSerializer,
    HealthcareDocumentSerializer,
    SensitiveDataFindingSerializer,
)
from documents.services import (
    audit_event,
    create_anonymization_job,
    create_document_from_upload,
    create_document_version,
    document_name,
    document_text,
    is_privileged,
    record_access_event,
    resolve_organization,
)
from documents.tasks import (
    access_monitoring_task,
    analyze_document_task,
    anonymization_task,
    process_document_task,
)
from documents.validators import validate_document_upload


def queue_task(task, *args, **kwargs):
    try:
        async_result = task.delay(*args, **kwargs)
        return {"queued": True, "task_id": str(getattr(async_result, "id", "") or "")}
    except Exception:
        return {"queued": False, "task_id": ""}


def _download_response(instance, field_name, fallback_name, fallback_text=""):
    field_file = getattr(instance, field_name, None)
    if field_file is not None and field_file.name:
        field_file.open("rb")
        response = FileResponse(field_file, as_attachment=True, filename=field_file.name.split("/")[-1])
        return response
    if fallback_text:
        response = HttpResponse(fallback_text, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{fallback_name}.txt"'
        return response
    return Response({"detail": "No file is available for download."}, status=status.HTTP_404_NOT_FOUND)


class DocumentViewSet(ModelViewSet):
    serializer_class = HealthcareDocumentSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(HealthcareDocument.objects.select_related("organization").all(), self.request)

    def create(self, request, *args, **kwargs):
        upload = None
        for field_name in ("file", "document", "upload", "raw_file"):
            upload = request.FILES.get(field_name)
            if upload is not None:
                break
        if upload is None:
            return Response({"detail": "A multipart file is required."}, status=status.HTTP_400_BAD_REQUEST)
        organization_id = request.data.get("organization") or request.data.get("organization_id")
        try:
            organization = resolve_organization(organization_id, request.user)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        if organization is None:
            return Response({"detail": "No organization is available."}, status=status.HTTP_400_BAD_REQUEST)
        max_bytes = int(getattr(settings, "MAX_UPLOAD_SIZE_MB", 10)) * 1024 * 1024
        try:
            raw_bytes, extension, digest = validate_document_upload(upload, max_bytes)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        upload.seek(0)
        document = create_document_from_upload(
            upload,
            organization,
            created_by=request.user,
            filename=upload.name,
            title=str(request.data.get("title") or "") or upload.name,
            is_synthetic=bool(request.data.get("is_synthetic", True)),
        )
        create_document_version(document, raw_bytes, upload.name, request.user, note="Initial upload")
        queued = queue_task(process_document_task, document.pk)
        audit_event(
            user=request.user,
            action="DOCUMENT_UPLOADED",
            organization=organization,
            document=document,
            detail=f"Uploaded document {document.pk}",
            request=request,
            target_type="HealthcareDocument",
            target_id=str(document.pk),
            metadata={"extension": extension, "sha256": digest},
        )
        data = self.get_serializer(document, context={"request": request}).data
        data["task"] = queued
        return Response(data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, pk=None):
        document = self.get_object()
        record_access_event(document, user=request.user, action="DOWNLOAD", request=request, actor_label="")
        return _download_response(document, "file", document_name(document), document_text(document))

    @action(detail=True, methods=["post"], url_path="analyze")
    def analyze(self, request, pk=None):
        document = self.get_object()
        queued = queue_task(analyze_document_task, document.pk, str(request.user.pk))
        audit_event(
            user=request.user,
            action="DOCUMENT_ANALYSIS_REQUESTED",
            organization=document.organization,
            document=document,
            detail=f"Analysis requested for document {document.pk}",
            request=request,
        )
        return Response({"document_id": str(document.pk), "task": queued}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["post"], url_path="anonymize")
    def anonymize(self, request, pk=None):
        document = self.get_object()
        rules = request.data.get("rules") or request.data.get("replacement_rules") or {}
        output_format = str(request.data.get("output_format") or "TXT").upper()
        job = create_anonymization_job(document, rules, output_format, request.user)
        queued = queue_task(anonymization_task, job.pk)
        return Response(
            {"job_id": str(job.pk), "document_id": str(document.pk), "task": queued},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["get", "post"], url_path="access")
    def access(self, request, pk=None):
        document = self.get_object()
        if request.method == "GET":
            queryset = AccessEvent.objects.filter(document=document).select_related("document")
            return Response(AccessEventSerializer(queryset, many=True, context={"request": request}).data)
        action_name = str(request.data.get("action") or "VIEW").upper()
        event = record_access_event(
            document,
            user=request.user,
            action=action_name,
            request=request,
            actor_label=str(request.data.get("actor_label") or ""),
        )
        return Response(
            AccessEventSerializer(event, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class DocumentVersionViewSet(ModelViewSet):
    serializer_class = DocumentVersionSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(
            DocumentVersion.objects.select_related("document", "document__organization").all(),
            self.request,
            field="document__organization",
        )

    def perform_create(self, serializer):
        document = serializer.validated_data.get("document")
        if document is not None and not is_privileged(self.request.user, document.organization):
            from rest_framework.exceptions import PermissionDenied

            raise PermissionDenied("Only reviewers and admins may add versions manually.")
        serializer.save(created_by=self.request.user)


class FindingViewSet(ModelViewSet):
    serializer_class = SensitiveDataFindingSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    http_method_names = ["get", "post", "patch", "head", "options"]

    def get_queryset(self):
        return scoped_queryset(
            SensitiveDataFinding.objects.select_related("document", "organization").all(),
            self.request,
        )

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request, pk=None):
        finding = self.get_object()
        result = review_finding(finding, request.user, request.data.get("status"), request=request)
        if result is None:
            return Response({"detail": "Reviewer or admin role is required."}, status=status.HTTP_403_FORBIDDEN)
        return Response(result)


class AnonymizationJobViewSet(ModelViewSet):
    serializer_class = AnonymizationJobSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        return scoped_queryset(AnonymizationJob.objects.select_related("document", "organization").all(), self.request)

    def perform_create(self, serializer):
        document = serializer.validated_data.get("document")
        organization = document.organization if document is not None else self.request.user.organization
        serializer.save(created_by=self.request.user, organization=organization, status=AnonymizationJob.Status.PENDING)

    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, pk=None):
        job = self.get_object()
        record_access_event(
            job.document,
            user=request.user,
            action="ANONYMIZED_DOWNLOAD",
            request=request,
            actor_label="",
        )
        return _download_response(job, "output_file", f"anonymized-{job.document_id}")


class AccessEventViewSet(ModelViewSet):
    serializer_class = AccessEventSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    http_method_names = ["get", "post", "head", "options"]

    def get_queryset(self):
        return scoped_queryset(
            AccessEvent.objects.select_related("document", "organization", "user").all(),
            self.request,
        )

    def perform_create(self, serializer):
        document = serializer.validated_data.get("document")
        serializer.save(
            organization=document.organization if document is not None else self.request.user.organization,
            user=self.request.user,
        )

    @action(detail=False, methods=["post"], url_path="monitor")
    def monitor(self, request, pk=None):
        if not is_privileged(request.user):
            return Response({"detail": "Reviewer or admin role is required."}, status=status.HTTP_403_FORBIDDEN)
        organization_id = request.data.get("organization") or request.data.get("organization_id")
        try:
            organization = resolve_organization(organization_id, request.user)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        if organization is None:
            return Response({"detail": "No organization is available."}, status=status.HTTP_400_BAD_REQUEST)
        queued = queue_task(access_monitoring_task, organization.pk)
        return Response(
            {"organization_id": str(organization.pk), "task": queued},
            status=status.HTTP_202_ACCEPTED,
        )


class AccessAlertViewSet(ModelViewSet):
    serializer_class = AccessAlertSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self):
        return scoped_queryset(AccessAlert.objects.select_related("organization", "event").all(), self.request)

    def perform_update(self, serializer):
        if str(serializer.validated_data.get("status", "")).upper() == AccessAlert.Status.ACKNOWLEDGED:
            serializer.save(acknowledged_by=self.request.user)
        else:
            serializer.save()
