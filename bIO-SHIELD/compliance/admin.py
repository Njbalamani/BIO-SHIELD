from django.contrib import admin

from .models import ComplianceChecklist, PrivacyAssessment


@admin.register(PrivacyAssessment)
class PrivacyAssessmentAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "document", "assessor_type", "risk_level", "status", "created_at")
    list_filter = ("assessor_type", "risk_level", "status", "organization")
    readonly_fields = ("created_at",)


@admin.register(ComplianceChecklist)
class ComplianceChecklistAdmin(admin.ModelAdmin):
    list_display = ("title", "framework", "organization", "status", "score", "created_at")
    list_filter = ("framework", "status", "organization")
    readonly_fields = ("created_at", "updated_at")
