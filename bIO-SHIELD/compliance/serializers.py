from rest_framework import serializers

from .models import ComplianceChecklist, PrivacyAssessment


class PrivacyAssessmentSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    document_title = serializers.CharField(source="document.title", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = PrivacyAssessment
        fields = (
            "id",
            "document",
            "document_title",
            "organization",
            "organization_name",
            "created_by",
            "created_by_username",
            "assessor_type",
            "status",
            "risk_score",
            "risk_level",
            "indicators",
            "recommendations",
            "findings_snapshot",
            "disclaimer",
            "created_at",
        )
        read_only_fields = (
            "id",
            "organization_name",
            "document_title",
            "created_by",
            "created_by_username",
            "created_at",
        )


class ComplianceChecklistSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    assessment_id_label = serializers.IntegerField(source="assessment_id", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = ComplianceChecklist
        fields = (
            "id",
            "organization",
            "organization_name",
            "assessment",
            "assessment_id_label",
            "framework",
            "title",
            "items",
            "responses",
            "score",
            "status",
            "created_by",
            "created_by_username",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "organization_name",
            "assessment_id_label",
            "created_by",
            "created_by_username",
            "created_at",
            "updated_at",
        )
