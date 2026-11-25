import hashlib
import io
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from docx import Document as DocxDocument
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from accounts.models import User
from analysis.engines.extraction import extract_text
from audit.models import AuditLog
from compliance.models import PrivacyAssessment
from documents.models import AccessAlert, AccessEvent, AnonymizationJob, HealthcareDocument, SensitiveDataFinding
from documents.services import (
    create_anonymization_job,
    create_document_from_upload,
    create_document_version,
    persist_findings,
    process_document,
    record_access_event,
    run_access_monitoring,
    run_anonymization_job,
)
from documents.validators import validate_document_upload
from organizations.models import Organization


def _pdf_bytes(text):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 11)
    pdf.drawString(72, 750, text)
    pdf.save()
    return buffer.getvalue()


def _docx_bytes(text):
    document = DocxDocument()
    document.add_paragraph(text)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


class UploadValidationTests(unittest.TestCase):
    def test_accepts_txt_pdf_and_docx_uploads(self):
        cases = (
            ("synthetic.txt", b"Synthetic TXT content", ".txt"),
            ("synthetic.pdf", _pdf_bytes("SYNTHETIC PDF CONTENT"), ".pdf"),
            ("synthetic.docx", _docx_bytes("SYNTHETIC DOCX CONTENT"), ".docx"),
        )

        for name, payload, expected_extension in cases:
            with self.subTest(name=name):
                uploaded = SimpleUploadedFile(name, payload)

                validated, extension, digest = validate_document_upload(uploaded, 1024 * 1024)

                self.assertEqual(validated, payload)
                self.assertEqual(extension, expected_extension)
                self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

    def test_rejects_unsupported_extension_and_empty_upload(self):
        with self.assertRaisesRegex(ValueError, "Unsupported document extension"):
            validate_document_upload(SimpleUploadedFile("synthetic.exe", b"placeholder"), 1024)

        with self.assertRaisesRegex(ValueError, "empty"):
            validate_document_upload(SimpleUploadedFile("synthetic.txt", b""), 1024)

    def test_rejects_invalid_txt_pdf_and_docx_content(self):
        with self.assertRaisesRegex(ValueError, "null bytes"):
            validate_document_upload(SimpleUploadedFile("synthetic.txt", b"Synthetic\x00text"), 1024)

        with self.assertRaisesRegex(ValueError, "invalid header"):
            validate_document_upload(SimpleUploadedFile("synthetic.pdf", b"NOT A PDF"), 1024)

        with self.assertRaisesRegex(ValueError, "invalid zip structure"):
            validate_document_upload(SimpleUploadedFile("synthetic.docx", b"not a zip"), 1024)

    def test_rejects_declared_and_streamed_oversize_uploads(self):
        declared = SimpleUploadedFile("synthetic.txt", b"x" * 64)
        declared.size = 1024
        stream = SimpleNamespace(name="synthetic.txt", read=io.BytesIO(b"x" * 64).read)

        with self.assertRaisesRegex(ValueError, "exceeds maximum size"):
            validate_document_upload(declared, 32)
        with self.assertRaisesRegex(ValueError, "exceeds maximum size"):
            validate_document_upload(stream, 32)

    def test_rejects_non_positive_size_limit(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            validate_document_upload(SimpleUploadedFile("synthetic.txt", b"placeholder"), 0)


class TextExtractionTests(unittest.TestCase):
    def test_extracts_text_and_metadata_from_txt(self):
        text, metadata = extract_text(b"Synthetic TXT content", "txt")

        self.assertEqual(text, "Synthetic TXT content")
        self.assertEqual(metadata["extension"], ".txt")
        self.assertEqual(metadata["char_count"], len(text))

    def test_extracts_text_and_page_count_from_pdf(self):
        text, metadata = extract_text(_pdf_bytes("SYNTHETIC PDF TEXT"), ".pdf")

        self.assertIn("SYNTHETIC PDF TEXT", text)
        self.assertEqual(metadata["extension"], ".pdf")
        self.assertEqual(metadata["page_count"], 1)

    def test_extracts_paragraphs_from_docx(self):
        text, metadata = extract_text(_docx_bytes("SYNTHETIC DOCX PARAGRAPH"), "docx")

        self.assertIn("SYNTHETIC DOCX PARAGRAPH", text)
        self.assertEqual(metadata["extension"], ".docx")
        self.assertEqual(metadata["paragraph_count"], 1)

    def test_rejects_non_bytes_and_invalid_document_content(self):
        with self.assertRaisesRegex(ValueError, "must be bytes"):
            extract_text("Synthetic text", "txt")
        with self.assertRaisesRegex(ValueError, "invalid content"):
            extract_text(b"Synthetic\x00text", ".txt")
        with self.assertRaisesRegex(ValueError, "Unsupported document extension"):
            extract_text(b"placeholder", ".exe")


class DocumentServiceTests(TestCase):
    def setUp(self):
        temporary_media = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_media.cleanup)
        media_override = override_settings(MEDIA_ROOT=temporary_media.name)
        media_override.enable()
        self.addCleanup(media_override.disable)

        self.organization = Organization.objects.create(name="SYNTHETIC DOC ORG", slug="synthetic-doc-org")
        self.user = User.objects.create_user(
            username="synth-uploader",
            password="SyntheticPass123!",
            email="uploader@example.invalid",
            organization=self.organization,
        )
        self.document = HealthcareDocument.objects.create(
            organization=self.organization,
            uploaded_by=self.user,
            title="Synthetic baseline document",
            original_filename="synthetic.txt",
            file="",
            file_type=HealthcareDocument.FileType.TXT,
            sha256="2" * 64,
            status=HealthcareDocument.Status.PENDING,
            is_synthetic=True,
        )

    def test_create_document_from_upload_hashes_bytes_and_marks_synthetic(self):
        payload = b"Synthetic upload content"

        document = create_document_from_upload(
            SimpleUploadedFile("synthetic.txt", payload),
            self.organization,
            created_by=self.user,
        )

        self.assertEqual(document.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(document.size_bytes, len(payload))
        self.assertEqual(document.file_type, HealthcareDocument.FileType.TXT)
        self.assertTrue(document.is_synthetic)
        self.assertEqual(document.status, HealthcareDocument.Status.PENDING)

    @override_settings(MAX_UPLOAD_SIZE_MB=1)
    @patch("analysis.services.detect_findings")
    def test_process_document_extracts_text_and_persists_assessment(self, mocked_detect):
        text = "Synthetic email synth.user@example.invalid"
        email = "synth.user@example.invalid"
        finding = {
            "finding_type": "EMAIL",
            "category": "CONTACT",
            "severity": "HIGH",
            "confidence": 0.98,
            "raw_value": email,
            "start_offset": text.index(email),
            "end_offset": text.index(email) + len(email),
        }
        mocked_detect.return_value = ([finding], {"warnings": []})
        document = create_document_from_upload(
            SimpleUploadedFile("synthetic.txt", text.encode("utf-8")),
            self.organization,
            created_by=self.user,
        )

        result = process_document(document.pk)

        document.refresh_from_db()
        assessment = PrivacyAssessment.objects.get(document=document)
        self.assertEqual(document.status, HealthcareDocument.Status.COMPLETED)
        self.assertEqual(document.text_extract, text)
        self.assertEqual(result["findings_count"], 1)
        self.assertEqual(SensitiveDataFinding.objects.filter(document=document).count(), 1)
        self.assertTrue(assessment.indicators)
        self.assertTrue(assessment.recommendations)
        self.assertTrue(AuditLog.objects.filter(action="DOCUMENT_PROCESSED").exists())

    @override_settings(MAX_UPLOAD_SIZE_MB=1)
    def test_process_document_rejects_oversize_upload_before_analysis(self):
        payload = b"x" * (1024 * 1024 + 1)
        document = create_document_from_upload(
            SimpleUploadedFile("oversize.txt", payload),
            self.organization,
            created_by=self.user,
        )

        with self.assertRaisesRegex(ValueError, "exceeds maximum size"):
            process_document(document.pk)

        document.refresh_from_db()
        self.assertEqual(document.status, HealthcareDocument.Status.PENDING)
        self.assertFalse(SensitiveDataFinding.objects.filter(document=document).exists())

    def test_create_document_version_increments_version_numbers(self):
        first = create_document_version(self.document, b"Synthetic v1", "synthetic.txt", self.user)
        second = create_document_version(self.document, b"Synthetic v2", "synthetic.txt", self.user)

        self.assertEqual(first.version_number, 1)
        self.assertEqual(second.version_number, 2)
        self.assertEqual(second.sha256, hashlib.sha256(b"Synthetic v2").hexdigest())

    def test_record_access_event_sanitizes_action_and_uses_forwarded_ip(self):
        request = RequestFactory().post(
            "/api/v1/documents/",
            HTTP_X_FORWARDED_FOR="203.0.113.7, 198.51.100.1",
            HTTP_USER_AGENT="SyntheticTest/1.0",
        )

        event = record_access_event(self.document, user=self.user, action="DELETEVERYTHING", request=request)

        self.assertEqual(event.action, "API")
        self.assertEqual(event.ip_address, "203.0.113.7")
        self.assertEqual(event.actor_label, self.user.email)
        self.assertEqual(event.user_agent, "SyntheticTest/1.0")

    def test_run_anonymization_job_creates_redacted_output_and_summary(self):
        text = "Synthetic synth.user@example.invalid SSN 000-00-0001"
        email = "synth.user@example.invalid"
        ssn = "000-00-0001"
        self.document.text_extract = text
        self.document.save(update_fields=["text_extract"])
        persist_findings(
            self.document,
            [
                {
                    "finding_type": "EMAIL",
                    "category": "CONTACT",
                    "severity": "HIGH",
                    "confidence": 0.98,
                    "raw_value": email,
                    "start_offset": text.index(email),
                    "end_offset": text.index(email) + len(email),
                },
                {
                    "finding_type": "SSN",
                    "category": "PHI",
                    "severity": "CRITICAL",
                    "confidence": 0.99,
                    "raw_value": ssn,
                    "start_offset": text.index(ssn),
                    "end_offset": text.index(ssn) + len(ssn),
                },
            ],
            created_by=self.user,
        )
        job = create_anonymization_job(self.document, {"EMAIL": "[EMAIL_SYNTH]"}, "TXT", self.user)

        result = run_anonymization_job(job.pk)

        job.refresh_from_db()
        with job.output_file.open("rb") as handle:
            output = handle.read().decode("utf-8")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(job.status, AnonymizationJob.Status.COMPLETED)
        self.assertNotIn(email, output)
        self.assertNotIn(ssn, output)
        self.assertIn("[EMAIL_SYNTH]", output)
        self.assertIn("[REDACTED_PHI]", output)
        self.assertEqual(job.summary["redactions_applied"], 2)
        self.assertTrue(AuditLog.objects.filter(action="ANONYMIZATION_COMPLETED").exists())

    def test_run_access_monitoring_creates_alerts_and_flags_events(self):
        for index, ip_address in enumerate(("198.51.100.11", "198.51.100.12", "198.51.100.13")):
            AccessEvent.objects.create(
                document=self.document,
                organization=self.organization,
                actor_label="SYNTHETIC_ACTOR",
                action=AccessEvent.Action.DOWNLOAD,
                ip_address=ip_address,
                metadata={"synthetic": True, "sequence": index},
            )

        result = run_access_monitoring(self.organization.pk)

        self.assertEqual(result["events_checked"], 3)
        self.assertGreaterEqual(result["alerts_created"], 2)
        self.assertEqual(AccessAlert.objects.filter(organization=self.organization).count(), result["alerts_created"])
        self.assertEqual(AccessEvent.objects.filter(anomaly_flag=True).count(), 3)
        self.assertTrue(AccessAlert.objects.filter(title="Rapid repeated downloads").exists())
        self.assertTrue(AuditLog.objects.filter(action="ACCESS_MONITORING_COMPLETED").exists())
