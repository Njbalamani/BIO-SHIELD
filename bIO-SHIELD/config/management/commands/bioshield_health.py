import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder

from accounts.models import User
from analysis import services as analysis_services
from audit.models import AuditLog
from compliance.models import ComplianceChecklist, PrivacyAssessment
from documents.models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)
from organizations.models import Organization
from reports.models import Report

EXPECTED_DISCLAIMER = "Automated assessment is not legal certification."
PROJECT_APP_LABELS = (
    "accounts",
    "organizations",
    "audit",
    "documents",
    "analysis",
    "compliance",
    "reports",
    "dashboard",
)
SAMPLE_FILES = (
    "generate_synthetic_documents.py",
    "synthetic_patient_summary.txt",
    "synthetic_clinical_notes.txt",
    "synthetic_patient_summary.pdf",
    "synthetic_clinical_notes.docx",
)
MODEL_COUNTS = (
    ("organizations", Organization),
    ("users", User),
    ("documents", HealthcareDocument),
    ("document_versions", DocumentVersion),
    ("findings", SensitiveDataFinding),
    ("anonymization_jobs", AnonymizationJob),
    ("access_events", AccessEvent),
    ("access_alerts", AccessAlert),
    ("assessments", PrivacyAssessment),
    ("checklists", ComplianceChecklist),
    ("reports", Report),
    ("audit_logs", AuditLog),
)


class Command(BaseCommand):
    help = "Verify BioShield deployment health and configuration."
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Write the report as JSON.")

    def handle(self, *args, **options):
        checks = {
            "database": self.check_database(),
            "migrations": self.check_migrations(),
            "staticfiles": self.check_staticfiles(),
            "synthetic_samples": self.check_synthetic_samples(),
            "ai_disclaimer": self.check_ai_disclaimer(),
            "synthetic_only": self.check_synthetic_only(),
            "field_encryption": self.check_field_encryption(),
            "model_counts": self.check_model_counts(),
        }
        failed = [name for name, check in checks.items() if check["critical"] and check["status"] != "ok"]
        payload = {
            "status": "ok" if not failed else "error",
            "ok": not failed,
            "failed_checks": [name for name, check in checks.items() if check["status"] != "ok"],
            "failed_critical_checks": failed,
            "checks": checks,
        }
        if options["json"]:
            self.stdout.write(json.dumps(payload, indent=2))
        else:
            self.write_report(payload)
        if failed:
            raise CommandError("BioShield health checks failed: " + ", ".join(failed))

    @staticmethod
    def make_check(label, passed, message, details=None):
        return {
            "label": label,
            "status": "ok" if passed else "fail",
            "passed": bool(passed),
            "critical": True,
            "message": message,
            "details": details or {},
        }

    def write_report(self, payload):
        heading = "BioShield health check: OK" if payload["ok"] else "BioShield health check: FAILED"
        if payload["ok"]:
            self.stdout.write(self.style.SUCCESS(heading))
        else:
            self.stdout.write(self.style.ERROR(heading))
        for check in payload["checks"].values():
            marker = "OK" if check["status"] == "ok" else "FAIL"
            if check["status"] == "ok":
                marker = self.style.SUCCESS(marker)
            else:
                marker = self.style.ERROR(marker)
            self.stdout.write(f"  [{marker}] {check['label']}: {check['message']}")
        if not payload["ok"]:
            self.stdout.write(self.style.ERROR("Critical failures: " + ", ".join(payload["failed_critical_checks"])))

    def check_database(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except Exception as exc:
            return self.make_check(
                "Database",
                False,
                f"Database unavailable ({type(exc).__name__}).",
                {"error": type(exc).__name__},
            )
        return self.make_check(
            "Database",
            True,
            f"Database available ({connection.vendor}).",
            {"vendor": connection.vendor},
        )

    def check_migrations(self):
        try:
            loader = MigrationLoader(connection)
            applied = set(MigrationRecorder(connection).applied_migrations())
            expected = {key for key in loader.disk_migrations if key[0] in PROJECT_APP_LABELS}
            missing_nodes = expected - applied
            missing = sorted(f"{app}.{migration}" for app, migration in missing_nodes)
            by_app = {}
            for label in PROJECT_APP_LABELS:
                app_expected = sorted(name for app, name in expected if app == label)
                app_missing = sorted(name for app, name in missing_nodes if app == label)
                by_app[label] = {
                    "expected": len(app_expected),
                    "applied": len(app_expected) - len(app_missing),
                    "missing": app_missing,
                }
        except Exception as exc:
            return self.make_check(
                "Migrations",
                False,
                f"Migration state unavailable ({type(exc).__name__}).",
                {"error": type(exc).__name__},
            )
        details = {
            "expected": len(expected),
            "applied": len(expected) - len(missing),
            "missing": missing,
            "apps": by_app,
        }
        if missing:
            return self.make_check(
                "Migrations",
                False,
                "Missing project migrations: " + ", ".join(missing),
                details,
            )
        return self.make_check(
            "Migrations",
            True,
            f"All project migrations applied ({len(expected)} migrations).",
            details,
        )

    def check_staticfiles(self):
        configured_path = getattr(settings, "STATIC_ROOT", "")
        static_root = Path(configured_path) if configured_path else None
        present = bool(static_root and static_root.is_dir())
        details = {"path": str(static_root) if static_root else None}
        if present:
            return self.make_check(
                "Static files",
                True,
                f"Staticfiles directory present: {static_root}",
                details,
            )
        return self.make_check(
            "Static files",
            False,
            "Staticfiles directory is missing or not configured.",
            details,
        )

    def check_synthetic_samples(self):
        sample_root = Path(getattr(settings, "BASE_DIR", ".")) / "samples"
        present = []
        missing = []
        for filename in SAMPLE_FILES:
            target = sample_root / filename
            if target.is_file():
                present.append(filename)
            else:
                missing.append(filename)
        details = {"directory": str(sample_root), "present": present, "missing": missing}
        if missing:
            return self.make_check(
                "Synthetic samples",
                False,
                "Missing synthetic sample files: " + ", ".join(missing),
                details,
            )
        return self.make_check(
            "Synthetic samples",
            True,
            f"All synthetic sample files present ({len(present)}/{len(SAMPLE_FILES)}).",
            details,
        )

    def check_ai_disclaimer(self):
        try:
            status = analysis_services.ai_status() or {}
        except Exception as exc:
            return self.make_check(
                "AI disclaimer",
                False,
                f"AI status unavailable ({type(exc).__name__}).",
                {"error": type(exc).__name__},
            )
        raw_disclaimer = status.get("disclaimer") if hasattr(status, "get") else None
        disclaimer = raw_disclaimer.strip() if isinstance(raw_disclaimer, str) else ""
        details = {"disclaimer": disclaimer, "expected": EXPECTED_DISCLAIMER}
        if disclaimer != EXPECTED_DISCLAIMER:
            return self.make_check(
                "AI disclaimer",
                False,
                "AI status disclaimer is missing or incorrect.",
                details,
            )
        return self.make_check("AI disclaimer", True, disclaimer, details)

    def check_synthetic_only(self):
        enabled = bool(getattr(settings, "SYNTHETIC_DATA_ONLY", False))
        if enabled:
            return self.make_check(
                "Synthetic-only mode",
                True,
                "Synthetic-only setting is enabled.",
                {"enabled": True},
            )
        return self.make_check(
            "Synthetic-only mode",
            False,
            "Synthetic-only setting is disabled.",
            {"enabled": False},
        )

    def check_field_encryption(self):
        configured = bool(str(getattr(settings, "FIELD_ENCRYPTION_KEY", "") or "").strip())
        if configured:
            return self.make_check(
                "Field encryption",
                True,
                "Field encryption key is configured.",
                {"configured": True},
            )
        return self.make_check(
            "Field encryption",
            False,
            "Field encryption key is not configured.",
            {"configured": False},
        )

    def check_model_counts(self):
        counts = {}
        try:
            for label, model in MODEL_COUNTS:
                counts[label] = model.objects.count()
        except Exception as exc:
            return self.make_check(
                "Model counts",
                False,
                f"Model counts unavailable ({type(exc).__name__}).",
                {"error": type(exc).__name__, "counts": counts},
            )
        summary = ", ".join(f"{label}={count}" for label, count in counts.items())
        return self.make_check("Model counts", True, f"Model counts available: {summary}", {"counts": counts})
