from django.conf import settings
from django.db import models


class PrivacyAssessment(models.Model):
    class AssessorType(models.TextChoices):
        AUTOMATED = "AUTOMATED", "Automated"
        MANUAL = "MANUAL", "Manual"

    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    class RiskLevel(models.TextChoices):
        LOW = "LOW", "Low"
        MODERATE = "MODERATE", "Moderate"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    document = models.ForeignKey(
        "documents.HealthcareDocument",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assessments",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="assessments",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_assessments",
    )
    assessor_type = models.CharField(
        max_length=20,
        choices=AssessorType.choices,
        default=AssessorType.AUTOMATED,
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_level = models.CharField(max_length=20, choices=RiskLevel.choices, default=RiskLevel.LOW)
    indicators = models.JSONField(default=dict, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    findings_snapshot = models.JSONField(default=list, blank=True)
    disclaimer = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"Privacy assessment {self.pk}"


class ComplianceChecklist(models.Model):
    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        COMPLETED = "COMPLETED", "Completed"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="checklists",
    )
    assessment = models.ForeignKey(
        PrivacyAssessment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="checklists",
    )
    framework = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    items = models.JSONField(default=list, blank=True)
    responses = models.JSONField(default=dict, blank=True)
    score = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_checklists",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.title
