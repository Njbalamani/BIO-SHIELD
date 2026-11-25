from django.conf import settings
from django.db import models


class Report(models.Model):
    class Format(models.TextChoices):
        PDF = "PDF", "PDF"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="reports",
    )
    document = models.ForeignKey(
        "documents.HealthcareDocument",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    assessment = models.ForeignKey(
        "compliance.PrivacyAssessment",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_reports",
    )
    report_type = models.CharField(max_length=100)
    format = models.CharField(max_length=10, choices=Format.choices, default=Format.PDF)
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to="reports/", blank=True)
    summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.title
