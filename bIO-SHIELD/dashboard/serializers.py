from rest_framework import serializers


class DashboardSummarySerializer(serializers.Serializer):
    organization_id = serializers.IntegerField(read_only=True)
    document_count = serializers.IntegerField(read_only=True)
    finding_count = serializers.IntegerField(read_only=True)
    high_risk_count = serializers.IntegerField(read_only=True)
    open_alert_count = serializers.IntegerField(read_only=True)
    recent_assessment_count = serializers.IntegerField(read_only=True)
