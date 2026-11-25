import hashlib
import tempfile
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from accounts.models import User
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
from documents.services import audit_event
from organizations.models import Organization
from reports.models import Report
from reports.services import render_report_pdf

EXPECTED_DISCLAIMER = "Automated assessment is not legal certification."


class _BioShieldAPITestCase(APITestCase):
    @classmethod
    def setUpClass(cls):
        cls.media_directory = tempfile.TemporaryDirectory()
        cls.media_override = override_settings(MEDIA_ROOT=cls.media_directory.name)
        cls.media_override.enable()
        cls.addClassCleanup(cls.media_override.disable)
        cls.addClassCleanup(cls.media_directory.cleanup)
        super().setUpClass()

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Synthetic Org A", slug="synthetic-org-a")
        cls.other_org = Organization.objects.create(name="Synthetic Org B", slug="synthetic-org-b")
        cls.viewer = User.objects.create_user(
            username="viewer-a",
            email="viewer.a@synthetic.invalid",
            password="SyntheticPass123!",
            organization=cls.org,
            role=User.Role.VIEWER,
        )
        cls.analyst = User.objects.create_user(
            username="analyst-a",
            email="analyst.a@synthetic.invalid",
            password="SyntheticPass123!",
            organization=cls.org,
            role=User.Role.ANALYST,
        )
        cls.reviewer = User.objects.create_user(
            username="reviewer-a",
            email="reviewer.a@synthetic.invalid",
            password="SyntheticPass123!",
            organization=cls.org,
            role=User.Role.REVIEWER,
        )
        cls.outsider = User.objects.create_user(
            username="viewer-b",
            email="viewer.b@synthetic.invalid",
            password="SyntheticPass123!",
            organization=cls.other_org,
            role=User.Role.VIEWER,
        )

    def setUp(self):
        super().setUp()
        for target in ("documents.api.queue_task", "analysis.api.queue_task", "reports.api.queue_task"):
            patcher = patch(target, side_effect=self.queue_result)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client.credentials()

    def queue_result(self, task, *args, **kwargs):
        return {"queued": True, "task_id": "synthetic-task"}

    def authenticate(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return token

    @staticmethod
    def results(response):
        data = response.data
        return data["results"] if isinstance(data, dict) and "results" in data else data

    def make_document(self, organization, title="Synthetic document", uploaded_by=None, document_status=None):
        payload = b"Synthetic placeholder content for API testing."
        return HealthcareDocument.objects.create(
            organization=organization,
            uploaded_by=uploaded_by or self.viewer,
            title=title,
            original_filename="synthetic_note.txt",
            file=SimpleUploadedFile("synthetic_note.txt", payload, content_type="text/plain"),
            file_type=HealthcareDocument.FileType.TXT,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            text_extract=payload.decode("utf-8"),
            status=document_status or HealthcareDocument.Status.COMPLETED,
            is_synthetic=True,
        )

    def make_finding(self, document, ciphertext="", finding_status=SensitiveDataFinding.Status.OPEN):
        return SensitiveDataFinding.objects.create(
            document=document,
            organization=document.organization,
            category=SensitiveDataFinding.Category.PII,
            finding_type="SYNTHETIC_EMAIL",
            value_masked="[REDACTED]",
            value_ciphertext=ciphertext,
            fingerprint="synthetic-fingerprint",
            confidence=0.91,
            methodology="synthetic-rule",
            line_number=1,
            start_offset=0,
            end_offset=10,
            context_masked="Synthetic context [REDACTED]",
            severity=SensitiveDataFinding.Severity.MEDIUM,
            status=finding_status,
        )

    def make_assessment(self, document, risk_score=25):
        return PrivacyAssessment.objects.create(
            document=document,
            organization=document.organization,
            created_by=self.viewer,
            assessor_type=PrivacyAssessment.AssessorType.AUTOMATED,
            status=PrivacyAssessment.Status.COMPLETED,
            risk_score=risk_score,
            risk_level=PrivacyAssessment.RiskLevel.MODERATE,
            indicators=[],
            recommendations=[],
            findings_snapshot=[],
            disclaimer=EXPECTED_DISCLAIMER,
        )


class AuthenticationAPITests(_BioShieldAPITestCase):
    def test_unauthenticated_api_endpoints_are_denied(self):
        endpoints = (
            ("documents-list", "get", None),
            ("findings-list", "get", None),
            ("audit-logs-list", "get", None),
            ("dashboard-metrics", "get", None),
            ("ai-status", "get", None),
            ("auth-me", "get", None),
            ("auth-logout", "post", {}),
            ("reports-generate", "post", {"organization": self.org.pk}),
        )
        for name, method, payload in endpoints:
            with self.subTest(endpoint=name):
                if method == "get":
                    response = getattr(self.client, method)(reverse(name))
                else:
                    response = getattr(self.client, method)(reverse(name), payload, format="json")
                self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_register_creates_viewer_with_token_and_organization(self):
        payload = {
            "username": "synthetic-register",
            "email": "synthetic.register@synthetic.invalid",
            "password": "SyntheticPass123!",
            "organization": self.org.pk,
            "role": "ADMIN",
        }
        response = self.client.post(reverse("auth-register"), payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["token"])
        self.assertEqual(response.data["user"]["role"], User.Role.VIEWER)
        self.assertEqual(response.data["user"]["organization"], self.org.pk)
        user = User.objects.get(username=payload["username"])
        self.assertTrue(user.check_password(payload["password"]))
        self.assertEqual(user.role, User.Role.VIEWER)
        self.assertEqual(user.organization, self.org)

    def test_login_me_and_logout_flow(self):
        response = self.client.post(
            reverse("auth-login"),
            {"username": self.viewer.username, "password": "SyntheticPass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["token"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {response.data['token']}")
        me = self.client.get(reverse("auth-me"))
        self.assertEqual(me.status_code, status.HTTP_200_OK)
        self.assertEqual(me.data["username"], self.viewer.username)
        self.assertEqual(me.data["role"], User.Role.VIEWER)
        logout = self.client.post(reverse("auth-logout"))
        self.assertEqual(logout.status_code, status.HTTP_200_OK)
        self.assertEqual(logout.data["detail"], "Logged out.")
        self.assertFalse(Token.objects.filter(user=self.viewer).exists())
        after_logout = self.client.get(reverse("auth-me"))
        self.assertIn(after_logout.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_login_rejects_invalid_credentials(self):
        response = self.client.post(
            reverse("auth-login"),
            {"username": self.viewer.username, "password": "WrongSyntheticPass"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["detail"], "Invalid credentials.")


class DocumentAPITests(_BioShieldAPITestCase):
    def test_multipart_upload_creates_synthetic_txt_document(self):
        self.authenticate(self.viewer)
        upload = SimpleUploadedFile(
            "synthetic_upload.txt",
            b"Synthetic TXT payload for upload.",
            content_type="text/plain",
        )
        response = self.client.post(
            reverse("documents-list"),
            {
                "file": upload,
                "title": "Synthetic upload",
                "organization": self.org.pk,
                "is_synthetic": "true",
            },
            format="multipart",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["file_type"], "TXT")
        self.assertTrue(response.data["is_synthetic"])
        self.assertEqual(len(response.data["sha256"]), 64)
        self.assertTrue(response.data["task"]["queued"])
        document = HealthcareDocument.objects.get(pk=response.data["id"])
        self.assertEqual(document.organization, self.org)
        self.assertEqual(document.uploaded_by, self.viewer)
        self.assertTrue(DocumentVersion.objects.filter(document=document, version_number=1).exists())
        self.assertTrue(
            AuditLog.objects.filter(user=self.viewer, action="DOCUMENT_UPLOADED", organization=self.org).exists()
        )

    def test_organization_scoping_blocks_reading_other_org_documents(self):
        own_document = self.make_document(self.org, "Synthetic owned document")
        foreign_document = self.make_document(
            self.other_org,
            "Synthetic foreign document",
            uploaded_by=self.outsider,
        )
        self.authenticate(self.viewer)
        list_response = self.client.get(reverse("documents-list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        visible_ids = {item["id"] for item in self.results(list_response)}
        self.assertIn(own_document.pk, visible_ids)
        self.assertNotIn(foreign_document.pk, visible_ids)
        own_response = self.client.get(reverse("documents-detail", args=[own_document.pk]))
        self.assertEqual(own_response.status_code, status.HTTP_200_OK)
        foreign_response = self.client.get(reverse("documents-detail", args=[foreign_document.pk]))
        self.assertEqual(foreign_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_analyze_and_anonymize_custom_actions(self):
        document = self.make_document(self.org)
        self.authenticate(self.viewer)
        analyze = self.client.post(reverse("documents-analyze", args=[document.pk]), {}, format="json")
        self.assertEqual(analyze.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(analyze.data["document_id"], str(document.pk))
        self.assertTrue(analyze.data["task"]["queued"])
        self.assertTrue(AuditLog.objects.filter(action="DOCUMENT_ANALYSIS_REQUESTED", organization=self.org).exists())
        anonymize = self.client.post(
            reverse("documents-anonymize", args=[document.pk]),
            {"rules": {"EMAIL": "[REDACTED]"}, "output_format": "TXT"},
            format="json",
        )
        self.assertEqual(anonymize.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(anonymize.data["document_id"], str(document.pk))
        self.assertTrue(anonymize.data["task"]["queued"])
        job = AnonymizationJob.objects.get(pk=anonymize.data["job_id"])
        self.assertEqual(job.organization, self.org)
        self.assertEqual(job.replacement_rules, {"EMAIL": "[REDACTED]"})
        self.assertEqual(job.output_format, "TXT")
        self.assertEqual(job.status, AnonymizationJob.Status.PENDING)


class FindingReviewTests(_BioShieldAPITestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.fernet_key = Fernet.generate_key().decode()
        cls.synthetic_secret = "synthetic-review-value"

    def setUp(self):
        super().setUp()
        self.encryption_override = override_settings(FIELD_ENCRYPTION_KEY=self.fernet_key)
        self.encryption_override.enable()
        self.addCleanup(self.encryption_override.disable)
        self.document = self.make_document(self.org, "Synthetic finding document")
        self.finding = self.make_finding(
            self.document,
            ciphertext=Fernet(self.fernet_key.encode()).encrypt(self.synthetic_secret.encode()).decode(),
        )

    def test_non_privileged_user_cannot_review_and_values_stay_masked(self):
        self.authenticate(self.analyst)
        response = self.client.post(
            reverse("findings-review", args=[self.finding.pk]),
            {"status": "REMEDIATED"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "Reviewer or admin role is required.")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, SensitiveDataFinding.Status.OPEN)
        self.assertIsNone(self.finding.reviewed_at)
        list_response = self.client.get(reverse("findings-list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        items = self.results(list_response)
        self.assertTrue(items)
        self.assertTrue(all(item["value_masked"] == "[REDACTED]" for item in items))
        self.assertNotIn(self.synthetic_secret, str(items))

    def test_reviewer_can_review_and_receives_unmasked_value(self):
        self.authenticate(self.reviewer)
        response = self.client.post(
            reverse("findings-review", args=[self.finding.pk]),
            {"status": "FALSE_POSITIVE"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["finding_id"], str(self.finding.pk))
        self.assertEqual(response.data["value"], self.synthetic_secret)
        self.assertFalse(response.data["masked"])
        self.assertTrue(response.data["authorized"])
        self.assertEqual(response.data["status"], "FALSE_POSITIVE")
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, "FALSE_POSITIVE")
        self.assertEqual(self.finding.reviewed_by, self.reviewer)
        self.assertIsNotNone(self.finding.reviewed_at)
        log = AuditLog.objects.get(action="FINDING_REVIEWED", target_id=str(self.finding.pk))
        self.assertEqual(log.metadata["status"], "FALSE_POSITIVE")
        self.assertTrue(log.metadata["revealed"])
        self.assertNotIn(self.synthetic_secret, str(log.metadata))


class AccessEventMonitorTests(_BioShieldAPITestCase):
    def test_viewer_is_forbidden_from_running_monitor(self):
        self.authenticate(self.viewer)
        response = self.client.post(
            reverse("access-events-monitor"),
            {"organization": self.org.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "Reviewer or admin role is required.")

    def test_reviewer_can_queue_monitor(self):
        self.authenticate(self.reviewer)
        response = self.client.post(
            reverse("access-events-monitor"),
            {"organization": self.org.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data["organization_id"], str(self.org.pk))
        self.assertTrue(response.data["task"]["queued"])


class AuditLogTests(_BioShieldAPITestCase):
    def test_upload_creates_audit_log_with_safe_metadata(self):
        self.authenticate(self.viewer)
        upload = SimpleUploadedFile(
            "synthetic_audit.txt",
            b"Synthetic audit payload.",
            content_type="text/plain",
        )
        response = self.client.post(
            reverse("documents-list"),
            {"file": upload, "organization": self.org.pk},
            format="multipart",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logs = self.results(self.client.get(reverse("audit-logs-list")))
        upload_logs = [item for item in logs if item["action"] == "DOCUMENT_UPLOADED"]
        self.assertEqual(len(upload_logs), 1)
        metadata = upload_logs[0]["metadata"]
        self.assertEqual(metadata["extension"], ".txt")
        self.assertEqual(metadata["sha256"], response.data["sha256"])
        self.assertNotIn("raw", metadata)
        self.assertNotIn("content", metadata)

    def test_sensitive_metadata_is_sanitized_before_audit_log_creation(self):
        self.authenticate(self.viewer)
        audit_event(
            user=self.viewer,
            action="SYNTHETIC_SENSITIVE_METADATA",
            organization=self.org,
            detail="Synthetic detail",
            metadata={
                "raw": "synthetic-raw",
                "value": "synthetic-value",
                "password": "synthetic-password",
                "token": "synthetic-token",
                "secret": "synthetic-secret",
                "safe_key": "synthetic-safe",
            },
        )
        self.assertTrue(AuditLog.objects.filter(action="SYNTHETIC_SENSITIVE_METADATA").exists())
        logs = self.results(self.client.get(reverse("audit-logs-list")))
        targets = [item for item in logs if item["action"] == "SYNTHETIC_SENSITIVE_METADATA"]
        self.assertEqual(len(targets), 1)
        metadata = targets[0]["metadata"]
        self.assertEqual(metadata["safe_key"], "synthetic-safe")
        self.assertEqual(metadata["detail"], "Synthetic detail")
        for key in ("raw", "value", "password", "token", "secret"):
            self.assertNotIn(key, metadata)
        self.authenticate(self.outsider)
        outsider_logs = self.results(self.client.get(reverse("audit-logs-list")))
        self.assertFalse(any(item["action"] == "SYNTHETIC_SENSITIVE_METADATA" for item in outsider_logs))


class HealthAndStatusTests(_BioShieldAPITestCase):
    def test_public_liveness_endpoints(self):
        for name in ("health", "health-live", "healthz"):
            with self.subTest(endpoint=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.json(), {"status": "ok"})

    def test_readiness_endpoint_checks_database(self):
        response = self.client.get(reverse("health-ready"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {"status": "ok", "database": "available"})

    @override_settings(SYNTHETIC_DATA_ONLY=True)
    def test_ai_status_includes_disclaimer(self):
        self.authenticate(self.viewer)
        response = self.client.get(reverse("ai-status"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["disclaimer"], EXPECTED_DISCLAIMER)
        self.assertTrue(response.data["synthetic_data_only"])
        self.assertEqual(response.data["status"], "operational")
        self.assertTrue(all(response.data["engines"].values()))


class DashboardMetricsTests(_BioShieldAPITestCase):
    def setUp(self):
        super().setUp()
        self.document = self.make_document(self.org, "Synthetic metrics document")
        self.make_document(
            self.other_org,
            "Synthetic foreign metrics document",
            uploaded_by=self.outsider,
        )
        self.make_finding(self.document)
        self.make_assessment(self.document, risk_score=25)
        ComplianceChecklist.objects.create(
            organization=self.org,
            framework="SYNTHETIC-FRAMEWORK",
            title="Synthetic checklist",
            items=[],
            responses={},
            status=ComplianceChecklist.Status.COMPLETED,
            created_by=self.viewer,
        )
        Report.objects.create(
            organization=self.org,
            document=self.document,
            created_by=self.viewer,
            report_type="PRIVACY_ASSESSMENT",
            format=Report.Format.PDF,
            title="Synthetic report",
            summary={},
        )
        AccessEvent.objects.create(
            document=self.document,
            organization=self.org,
            user=self.viewer,
            action=AccessEvent.Action.VIEW,
            actor_label="SyntheticActor",
        )
        AnonymizationJob.objects.create(
            document=self.document,
            organization=self.org,
            created_by=self.viewer,
            status=AnonymizationJob.Status.COMPLETED,
        )
        AccessAlert.objects.create(
            organization=self.org,
            title="Synthetic alert",
            severity=AccessAlert.Severity.LOW,
        )

    def test_metrics_are_scoped_to_user_organization(self):
        self.authenticate(self.viewer)
        response = self.client.get(reverse("dashboard-metrics"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertTrue(data["generated_at"])
        self.assertEqual([item["id"] for item in data["organizations"]], [str(self.org.pk)])
        self.assertEqual(data["documents_total"], 1)
        self.assertEqual(data["documents_completed"], 1)
        self.assertEqual(data["documents_pending"], 0)
        self.assertEqual(data["findings_total"], 1)
        self.assertEqual(data["findings_by_severity"], {"MEDIUM": 1})
        self.assertEqual(data["findings_by_category"], {"PII": 1})
        self.assertEqual(data["assessments_total"], 1)
        self.assertEqual(data["average_risk_score"], 25.0)
        self.assertEqual(data["checklists_total"], 1)
        self.assertEqual(data["checklists_completed"], 1)
        self.assertEqual(data["reports_total"], 1)
        self.assertEqual(data["alerts_total"], 1)
        self.assertEqual(data["alerts_open"], 1)
        self.assertEqual(data["access_events_total"], 1)
        self.assertEqual(data["anonymization_jobs_total"], 1)
        self.assertEqual(data["anonymization_jobs_completed"], 1)


class ComplianceChecklistTests(_BioShieldAPITestCase):
    def test_checklist_creation_exposes_linked_assessment_disclaimer(self):
        document = self.make_document(self.org, "Synthetic compliance document")
        assessment = self.make_assessment(document)
        self.authenticate(self.viewer)
        response = self.client.post(
            reverse("checklists-list"),
            {
                "organization": self.org.pk,
                "assessment": assessment.pk,
                "framework": "SYNTHETIC-FRAMEWORK",
                "title": "Synthetic compliance checklist",
                "items": [{"id": "SYN-1", "question": "Synthetic check?"}],
                "responses": {},
                "status": ComplianceChecklist.Status.DRAFT,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["organization"], self.org.pk)
        self.assertEqual(response.data["assessment"], assessment.pk)
        self.assertEqual(response.data["score"], 0)
        self.assertEqual(response.data["created_by"], self.viewer.pk)
        assessments = self.results(self.client.get(reverse("assessments-list")))
        self.assertEqual(assessments[0]["disclaimer"], EXPECTED_DISCLAIMER)
        checklists = self.results(self.client.get(reverse("checklists-list")))
        self.assertEqual(checklists[0]["assessment_id_label"], assessment.pk)


class ReportTests(_BioShieldAPITestCase):
    def queue_result(self, task, *args, **kwargs):
        if getattr(task, "name", "") == "reports.pdf_report":
            render_report_pdf(str(args[0]))
        return {"queued": True, "task_id": "synthetic-task"}

    def test_generate_and_download_pdf_report(self):
        document = self.make_document(self.org, "Synthetic report document")
        self.authenticate(self.viewer)
        response = self.client.post(
            reverse("reports-generate"),
            {
                "organization": self.org.pk,
                "document": document.pk,
                "title": "Synthetic privacy report",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertTrue(response.data["task"]["queued"])
        report_id = response.data["report_id"]
        report = Report.objects.get(pk=report_id)
        self.assertEqual(report.organization, self.org)
        self.assertEqual(report.format, Report.Format.PDF)
        self.assertTrue(report.file.name.endswith(".pdf"))
        self.assertEqual(report.summary["disclaimer"], EXPECTED_DISCLAIMER)
        detail = self.client.get(reverse("reports-detail", args=[report.pk]))
        self.assertEqual(detail.status_code, status.HTTP_200_OK)
        self.assertEqual(detail.data["format"], "PDF")
        download = self.client.get(reverse("reports-download", args=[report.pk]))
        self.assertEqual(download.status_code, status.HTTP_200_OK)
        payload = b"".join(download.streaming_content)
        download.close()
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertIn("attachment", download["Content-Disposition"])

    def test_report_scoping_blocks_foreign_org_download(self):
        document = self.make_document(self.org)
        report = Report.objects.create(
            organization=self.org,
            document=document,
            report_type="PRIVACY_ASSESSMENT",
            format=Report.Format.PDF,
            title="Synthetic scoped report",
            summary={},
        )
        self.authenticate(self.outsider)
        detail = self.client.get(reverse("reports-detail", args=[report.pk]))
        self.assertEqual(detail.status_code, status.HTTP_404_NOT_FOUND)
        download = self.client.get(reverse("reports-download", args=[report.pk]))
        self.assertEqual(download.status_code, status.HTTP_404_NOT_FOUND)
