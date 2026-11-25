from django.contrib import admin

from .models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)


@admin.register(HealthcareDocument)
class HealthcareDocumentAdmin(admin.ModelAdmin):
    list_display = ("title", "organization", "file_type", "status", "created_at")
    list_filter = ("file_type", "status", "is_synthetic", "organization")
    search_fields = ("title", "original_filename", "sha256")
    readonly_fields = ("created_at", "updated_at")


@admin.register(DocumentVersion)
class DocumentVersionAdmin(admin.ModelAdmin):
    list_display = ("document", "version_number", "filename", "created_by", "created_at")
    list_filter = ("document__organization",)
    search_fields = ("filename", "sha256")
    readonly_fields = ("created_at",)


@admin.register(SensitiveDataFinding)
class SensitiveDataFindingAdmin(admin.ModelAdmin):
    list_display = ("document", "category", "finding_type", "severity", "status")
    list_filter = ("category", "severity", "status", "organization")
    search_fields = ("finding_type", "value_masked", "fingerprint")
    readonly_fields = ("created_at",)


@admin.register(AnonymizationJob)
class AnonymizationJobAdmin(admin.ModelAdmin):
    list_display = ("document", "organization", "status", "output_format", "created_at")
    list_filter = ("status", "output_format", "organization")
    readonly_fields = ("created_at", "finished_at")


@admin.register(AccessEvent)
class AccessEventAdmin(admin.ModelAdmin):
    list_display = ("document", "user", "actor_label", "action", "occurred_at", "anomaly_flag")
    list_filter = ("action", "anomaly_flag", "organization")
    readonly_fields = ("occurred_at",)


@admin.register(AccessAlert)
class AccessAlertAdmin(admin.ModelAdmin):
    list_display = ("title", "organization", "severity", "status", "created_at")
    list_filter = ("severity", "status", "organization")
    readonly_fields = ("created_at",)
