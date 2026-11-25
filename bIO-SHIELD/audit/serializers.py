from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    user_label = serializers.CharField(source="user.username", read_only=True)
    organization_name = serializers.CharField(source="organization.name", read_only=True)

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "user",
            "user_label",
            "organization",
            "organization_name",
            "action",
            "target_type",
            "target_id",
            "metadata",
            "ip_address",
            "created_at",
        )
        read_only_fields = fields
