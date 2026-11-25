from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    document_title = serializers.CharField(source="document.title", read_only=True)
    assessment_label = serializers.CharField(source="assessment.__str__", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = Report
        fields = (
            "id",
            "organization",
            "organization_name",
            "document",
            "document_title",
            "assessment",
            "assessment_label",
            "created_by",
            "created_by_username",
            "report_type",
            "format",
            "title",
            "file",
            "summary",
            "created_at",
        )
        read_only_fields = (
            "id",
            "organization_name",
            "document_title",
            "assessment_label",
            "created_by",
            "created_by_username",
            "created_at",
        )
