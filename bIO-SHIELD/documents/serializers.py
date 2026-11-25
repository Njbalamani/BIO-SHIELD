from rest_framework import serializers

from .models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)


class HealthcareDocumentSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    uploaded_by_username = serializers.CharField(source="uploaded_by.username", read_only=True)

    class Meta:
        model = HealthcareDocument
        fields = (
            "id",
            "organization",
            "organization_name",
            "uploaded_by",
            "uploaded_by_username",
            "title",
            "original_filename",
            "file",
            "file_type",
            "sha256",
            "size_bytes",
            "status",
            "is_synthetic",
            "retention_until",
            "last_analyzed_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "organization_name",
            "uploaded_by",
            "uploaded_by_username",
            "sha256",
            "size_bytes",
            "status",
            "last_analyzed_at",
            "created_at",
            "updated_at",
        )


class DocumentVersionSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="document.title", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = DocumentVersion
        fields = (
            "id",
            "document",
            "document_title",
            "version_number",
            "file",
            "filename",
            "sha256",
            "created_by",
            "created_by_username",
            "change_note",
            "created_at",
        )
        read_only_fields = (
            "id",
            "document_title",
            "sha256",
            "created_by",
            "created_by_username",
            "created_at",
        )


class SensitiveDataFindingSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="document.title", read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    reviewed_by_username = serializers.CharField(source="reviewed_by.username", read_only=True)

    class Meta:
        model = SensitiveDataFinding
        fields = (
            "id",
            "document",
            "document_title",
            "organization",
            "organization_name",
            "category",
            "finding_type",
            "value_masked",
            "fingerprint",
            "confidence",
            "methodology",
            "line_number",
            "start_offset",
            "end_offset",
            "context_masked",
            "severity",
            "status",
            "reviewed_by",
            "reviewed_by_username",
            "reviewed_at",
            "created_at",
        )
        read_only_fields = fields


class AnonymizationJobSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="document.title", read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = AnonymizationJob
        fields = (
            "id",
            "document",
            "document_title",
            "organization",
            "organization_name",
            "created_by",
            "created_by_username",
            "status",
            "replacement_rules",
            "output_format",
            "output_file",
            "summary",
            "warnings",
            "created_at",
            "finished_at",
        )
        read_only_fields = (
            "id",
            "document_title",
            "organization_name",
            "created_by",
            "created_by_username",
            "status",
            "output_file",
            "summary",
            "warnings",
            "created_at",
            "finished_at",
        )


class AccessEventSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="document.title", read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = AccessEvent
        fields = (
            "id",
            "document",
            "document_title",
            "organization",
            "organization_name",
            "user",
            "username",
            "actor_label",
            "action",
            "ip_address",
            "user_agent",
            "occurred_at",
            "anomaly_flag",
            "anomaly_reason",
            "metadata",
        )
        read_only_fields = fields


class AccessAlertSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    acknowledged_by_username = serializers.CharField(source="acknowledged_by.username", read_only=True)

    class Meta:
        model = AccessAlert
        fields = (
            "id",
            "organization",
            "organization_name",
            "event",
            "severity",
            "title",
            "reason",
            "status",
            "created_at",
            "acknowledged_by",
            "acknowledged_by_username",
        )
        read_only_fields = (
            "id",
            "organization_name",
            "created_at",
            "acknowledged_by",
            "acknowledged_by_username",
        )
