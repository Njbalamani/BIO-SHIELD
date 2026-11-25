from django.conf import settings
from django.db import models


class HealthcareDocument(models.Model):
    class FileType(models.TextChoices):
        PDF = "PDF", "PDF"
        TXT = "TXT", "TXT"
        DOCX = "DOCX", "DOCX"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PROCESSING = "PROCESSING", "Processing"
        COMPLETED = "COMPLETED", "Completed"
        WARNING = "WARNING", "Warning"
        FAILED = "FAILED", "Failed"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="documents",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_documents",
    )
    title = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255)
    file = models.FileField(upload_to="documents/")
    file_type = models.CharField(max_length=10, choices=FileType.choices)
    sha256 = models.CharField(max_length=64, db_index=True)
    size_bytes = models.PositiveBigIntegerField(default=0)
    text_extract = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    is_synthetic = models.BooleanField(default=True)
    retention_until = models.DateField(null=True, blank=True)
    last_analyzed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-pk")

    def __str__(self):
        return self.title


class DocumentVersion(models.Model):
    document = models.ForeignKey(HealthcareDocument, on_delete=models.CASCADE, related_name="versions")
    version_number = models.PositiveIntegerField()
    file = models.FileField(upload_to="document_versions/")
    filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="document_versions",
    )
    change_note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("document", "version_number")
        ordering = ("version_number",)

    def __str__(self):
        return f"{self.document.title} v{self.version_number}"


class SensitiveDataFinding(models.Model):
    class Category(models.TextChoices):
        PII = "PII", "PII"
        PHI = "PHI", "PHI"
        CONTACT = "CONTACT", "Contact"
        IDENTIFIER = "IDENTIFIER", "Identifier"
        MEDICAL = "MEDICAL", "Medical"
        OTHER = "OTHER", "Other"

    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        REVIEWED = "REVIEWED", "Reviewed"
        REMEDIATED = "REMEDIATED", "Remediated"
        FALSE_POSITIVE = "FALSE_POSITIVE", "False positive"

    document = models.ForeignKey(HealthcareDocument, on_delete=models.CASCADE, related_name="findings")
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    category = models.CharField(max_length=20, choices=Category.choices)
    finding_type = models.CharField(max_length=100)
    value_masked = models.CharField(max_length=255)
    value_ciphertext = models.TextField(blank=True)
    fingerprint = models.CharField(max_length=128, db_index=True)
    confidence = models.FloatField(default=0.0)
    methodology = models.CharField(max_length=100, blank=True)
    line_number = models.PositiveIntegerField(null=True, blank=True)
    start_offset = models.PositiveIntegerField(null=True, blank=True)
    end_offset = models.PositiveIntegerField(null=True, blank=True)
    context_masked = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.LOW)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_findings",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.finding_type} ({self.value_masked})"


class AnonymizationJob(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PROCESSING = "PROCESSING", "Processing"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    class OutputFormat(models.TextChoices):
        TXT = "TXT", "TXT"
        DOCX = "DOCX", "DOCX"
        PDF = "PDF", "PDF"

    document = models.ForeignKey(HealthcareDocument, on_delete=models.CASCADE, related_name="anonymization_jobs")
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="anonymization_jobs",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anonymization_jobs",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    replacement_rules = models.JSONField(default=dict, blank=True)
    output_format = models.CharField(max_length=10, choices=OutputFormat.choices, default=OutputFormat.TXT)
    output_file = models.FileField(upload_to="anonymized/", blank=True)
    summary = models.JSONField(default=dict, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at", "-pk")

    def __str__(self):
        return f"Anonymization job {self.pk}"


class AccessEvent(models.Model):
    class Action(models.TextChoices):
        VIEW = "VIEW", "View"
        DOWNLOAD = "DOWNLOAD", "Download"
        API = "API", "API"
        ANONYMIZED_DOWNLOAD = "ANONYMIZED_DOWNLOAD", "Anonymized download"

    document = models.ForeignKey(HealthcareDocument, on_delete=models.CASCADE, related_name="access_events")
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="access_events",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_events",
    )
    actor_label = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=30, choices=Action.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    anomaly_flag = models.BooleanField(default=False)
    anomaly_reason = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-occurred_at",)

    def __str__(self):
        return f"{self.action} on {self.document_id} at {self.occurred_at}"


class AccessAlert(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        ACKNOWLEDGED = "ACKNOWLEDGED", "Acknowledged"
        RESOLVED = "RESOLVED", "Resolved"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="access_alerts",
    )
    event = models.ForeignKey(
        AccessEvent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alerts",
    )
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MEDIUM)
    title = models.CharField(max_length=255)
    reason = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acknowledged_access_alerts",
    )

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.title
