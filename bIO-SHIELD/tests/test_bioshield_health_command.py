import json
from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

CHECK_NAMES = (
    "database",
    "migrations",
    "staticfiles",
    "synthetic_samples",
    "ai_disclaimer",
    "synthetic_only",
    "field_encryption",
    "model_counts",
)


class BioShieldHealthCommandTests(TestCase):
    def setUp(self):
        super().setUp()
        self.stdout = StringIO()
        self.stderr = StringIO()
        self.static_directory = TemporaryDirectory()
        self.addCleanup(self.static_directory.cleanup)
        self.settings_override = override_settings(
            STATIC_ROOT=self.static_directory.name,
            SYNTHETIC_DATA_ONLY=True,
            FIELD_ENCRYPTION_KEY="synthetic-field-encryption-key",
        )
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    def test_command_reports_success(self):
        call_command("bioshield_health", stdout=self.stdout, stderr=self.stderr)
        output = self.stdout.getvalue()
        self.assertIn("BioShield health check: OK", output)
        for label in (
            "Database",
            "Migrations",
            "Static files",
            "Synthetic samples",
            "AI disclaimer",
            "Synthetic-only mode",
            "Field encryption",
            "Model counts",
        ):
            with self.subTest(label=label):
                self.assertIn(label, output)
        self.assertNotIn("Critical failures", output)

    def test_command_json_mode(self):
        call_command("bioshield_health", "--json", stdout=self.stdout, stderr=self.stderr)
        payload = json.loads(self.stdout.getvalue())
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["failed_checks"], [])
        self.assertEqual(payload["failed_critical_checks"], [])
        for name in CHECK_NAMES:
            with self.subTest(check=name):
                self.assertEqual(payload["checks"][name]["status"], "ok")
        counts = payload["checks"]["model_counts"]["details"]["counts"]
        self.assertIn("organizations", counts)

    def test_command_fails_when_ai_disclaimer_is_missing(self):
        status = {"status": "operational"}
        with patch("analysis.services.ai_status", return_value=status):
            with self.assertRaises(CommandError):
                call_command(
                    "bioshield_health",
                    "--json",
                    stdout=self.stdout,
                    stderr=self.stderr,
                )
        payload = json.loads(self.stdout.getvalue())
        self.assertEqual(payload["status"], "error")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["checks"]["ai_disclaimer"]["status"], "fail")
        self.assertIn("ai_disclaimer", payload["failed_critical_checks"])
