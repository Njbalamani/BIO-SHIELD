from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "organization", "action", "target_type", "target_id")
    list_filter = ("action", "target_type", "organization")
    search_fields = ("user__username", "action", "target_type", "target_id")
    readonly_fields = ("created_at",)
