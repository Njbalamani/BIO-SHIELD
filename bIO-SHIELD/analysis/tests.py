import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.test import TestCase, override_settings

from accounts.models import User
from analysis.engines import mask_value, safe_preview, sha256_text
from analysis.engines.access import detect_anomalies
from analysis.engines.anonymization import apply_redaction
from analysis.engines.detection import detect_findings
from analysis.engines.risk import calculate_privacy_risk
from analysis.services import mask_for_review, run_document_analysis
from compliance.models import PrivacyAssessment
from documents.models import HealthcareDocument, SensitiveDataFinding
from documents.services import decrypt_secret, persist_findings
from organizations.models import Organization


def _finding_types(findings):
    return {str(finding["finding_type"]) for finding in findings}


def _access_event(label, action, hour, minute, ip_address):
    return {
        "actor_label": label,
        "action": action,
        "occurred_at": datetime(2026, 1, 1, hour, minute, tzinfo=UTC),
        "ip_address": ip_address,
    }


class RegexDetectionTests(unittest.TestCase):
    CONTACT_TEXT = "Synthetic contact: synth.user@example.invalid, (555) 010-0199, 000-00-0001, MRN: SYN-MRN-0001."
    CLINICAL_TEXT = "DOB: 1900-01-01. ICD-10: E11.9. Medication: Metformin. Diagnosis: Hypertension."

    def test_detects_synthetic_email_phone_ssn_and_mrn(self):
        findings, summary = detect_findings(self.CONTACT_TEXT, use_presidio=False, use_spacy=False)

        self.assertTrue({"EMAIL", "PHONE", "SSN", "MRN"}.issubset(_finding_types(findings)))
        self.assertEqual(summary["total_findings"], len(findings))
        self.assertEqual(summary["counts_by_finding_type"]["SSN"], 1)
        self.assertIn("regex", summary["methodologies"])

    def test_detects_synthetic_dob_icd10_medication_and_diagnosis(self):
        findings, _ = detect_findings(self.CLINICAL_TEXT, use_presidio=False, use_spacy=False)

        self.assertTrue({"DATE_OF_BIRTH", "ICD10_CODE", "MEDICATION", "DIAGNOSIS"}.issubset(_finding_types(findings)))

    def test_detection_masks_raw_values_and_produces_stable_fingerprints(self):
        raw_value = "000-00-0001"
        text = f"Synthetic record SSN {raw_value}"
        findings, _ = detect_findings(text, use_presidio=False, use_spacy=False)
        finding = next(item for item in findings if item["finding_type"] == "SSN")

        self.assertNotEqual(finding["value_masked"], raw_value)
        self.assertNotIn(raw_value, finding["context_masked"])
        self.assertEqual(finding["fingerprint"], sha256_text(f"SSN|{raw_value.casefold()}"))
        self.assertEqual(finding["line_number"], 1)

    def test_detection_summary_reports_disabled_optional_engines(self):
        _, summary = detect_findings(self.CONTACT_TEXT, use_presidio=False, use_spacy=False)

        self.assertFalse(summary["engines"]["presidio"])
        self.assertFalse(summary["engines"]["spacy"])
        self.assertEqual(summary["source_name"], "document")


class PrivacyRiskEngineTests(unittest.TestCase):
    BASE_FINDINGS = [
        {"category": "PHI", "finding_type": "SSN", "severity": "CRITICAL", "confidence": 0.99},
        {"category": "PHI", "finding_type": "MRN", "severity": "HIGH", "confidence": 0.93},
        {"category": "CLINICAL", "finding_type": "MEDICATION", "severity": "MODERATE", "confidence": 0.87},
        {"category": "CLINICAL", "finding_type": "DIAGNOSIS", "severity": "MODERATE", "confidence": 0.82},
    ]

    def test_empty_inputs_produce_low_risk_with_baseline_guidance(self):
        with patch("analysis.engines.risk._model_score", return_value=(None, "heuristic")):
            score, level, indicators, recommendations = calculate_privacy_risk([])

        self.assertEqual(score, 0.0)
        self.assertEqual(level, "LOW")
        self.assertEqual(
            {indicator["name"] for indicator in indicators},
            {
                "sensitivity_mix",
                "high_severity_count",
                "phi_count",
                "access_anomalies",
                "exposure_factor",
                "confidence_average",
                "risk_model_refinement",
            },
        )
        self.assertTrue(any("Retain current safeguards" in item for item in recommendations))
        self.assertTrue(any("Record remediation decisions" in item for item in recommendations))

    def test_sensitive_findings_increase_score_with_explainable_guidance(self):
        with patch("analysis.engines.risk._model_score", return_value=(None, "heuristic")):
            score, level, indicators, recommendations = calculate_privacy_risk(self.BASE_FINDINGS)

        by_name = {indicator["name"]: indicator for indicator in indicators}
        self.assertGreaterEqual(score, 45.0)
        self.assertIn(level, {"HIGH", "CRITICAL"})
        self.assertEqual(by_name["sensitivity_mix"]["value"], {"PHI": 2, "CLINICAL": 2})
        self.assertEqual(by_name["high_severity_count"]["value"], 2)
        self.assertEqual(by_name["phi_count"]["value"], 4)
        self.assertGreater(by_name["high_severity_count"]["weight"], 0)
        self.assertGreater(by_name["phi_count"]["weight"], 0)
        self.assertTrue(any("high and critical findings" in item for item in recommendations))
        self.assertTrue(any("PHI-bearing fields" in item for item in recommendations))
        self.assertTrue(any("clinical terms" in item for item in recommendations))

    def test_access_anomalies_and_exposure_increase_score_and_change_guidance(self):
        events = [
            _access_event("SYNTHETIC_ACTOR", "DOWNLOAD", 12, 0, "198.51.100.11"),
            _access_event("SYNTHETIC_ACTOR", "DOWNLOAD", 12, 1, "198.51.100.12"),
            _access_event("SYNTHETIC_ACTOR", "DOWNLOAD", 12, 2, "198.51.100.13"),
        ]
        with patch("analysis.engines.risk._model_score", return_value=(None, "heuristic")):
            baseline_score, _, _, _ = calculate_privacy_risk(self.BASE_FINDINGS)
            score, _, indicators, recommendations = calculate_privacy_risk(
                self.BASE_FINDINGS,
                access_events=events,
                exposure_factors={"external_share": True},
            )

        by_name = {indicator["name"]: indicator for indicator in indicators}
        self.assertGreater(score, baseline_score)
        self.assertGreaterEqual(by_name["access_anomalies"]["value"], 1)
        self.assertEqual(by_name["exposure_factor"]["value"], 0.9)
        self.assertTrue(any("Investigate flagged access events" in item for item in recommendations))
        self.assertTrue(any("Disable public links" in item for item in recommendations))


class AnonymizationEngineTests(unittest.TestCase):
    def test_replaces_raw_values_with_custom_and_category_replacements(self):
        text = "Synthetic synth.user@example.invalid SSN 000-00-0001"
        email = "synth.user@example.invalid"
        ssn = "000-00-0001"
        findings = [
            {
                "finding_type": "EMAIL",
                "category": "CONTACT",
                "severity": "HIGH",
                "confidence": 0.98,
                "start_offset": text.index(email),
                "end_offset": text.index(email) + len(email),
            },
            {
                "finding_type": "SSN",
                "category": "PHI",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "start_offset": text.index(ssn),
                "end_offset": text.index(ssn) + len(ssn),
            },
        ]

        sanitized, summary, warnings = apply_redaction(
            text, findings, rules={"EMAIL": "[EMAIL_SYNTH]"}, output_format="txt"
        )

        self.assertNotIn(email, sanitized)
        self.assertNotIn(ssn, sanitized)
        self.assertIn("[EMAIL_SYNTH]", sanitized)
        self.assertIn("[REDACTED_PHI]", sanitized)
        self.assertEqual(summary["redactions_applied"], 2)
        self.assertEqual(summary["replacements_by_finding_type"], {"EMAIL": 1, "SSN": 1})
        self.assertEqual(warnings, [])

    def test_skips_overlapping_and_invalid_spans(self):
        text = "SYNTHETIC VALUEABCDEFG"
        findings = [
            {
                "finding_type": "NAME",
                "category": "PII",
                "severity": "HIGH",
                "confidence": 0.9,
                "start_offset": 10,
                "end_offset": 15,
            },
            {
                "finding_type": "TOKEN",
                "category": "OTHER",
                "severity": "LOW",
                "confidence": 0.5,
                "start_offset": 12,
                "end_offset": 17,
            },
            {
                "finding_type": "ADDRESS",
                "category": "PII",
                "severity": "HIGH",
                "confidence": 0.8,
                "start_offset": 99,
                "end_offset": 105,
            },
        ]

        sanitized, summary, warnings = apply_redaction(text, findings)

        self.assertIn("[REDACTED_PII]", sanitized)
        self.assertNotIn("VALUE", sanitized)
        self.assertEqual(summary["redactions_applied"], 1)
        self.assertEqual(summary["skipped_overlapping_spans"], 1)
        self.assertEqual(summary["invalid_spans"], 1)
        self.assertTrue(any("Overlapping" in item for item in warnings))
        self.assertTrue(any("invalid offsets" in item for item in warnings))

    def test_masking_helpers_never_return_raw_synthetic_secret(self):
        raw_value = "000-00-0001"
        text = f"Synthetic SSN {raw_value}"

        self.assertEqual(mask_value(raw_value, keep=0), "*" * len(raw_value))
        self.assertEqual(mask_value(None), "[REDACTED]")
        preview = safe_preview(text, text.index(raw_value), text.index(raw_value) + len(raw_value))

        self.assertNotIn(raw_value, preview)
        self.assertNotEqual(preview, text)

    def test_unsupported_output_format_warns_and_falls_back_to_txt(self):
        _, summary, warnings = apply_redaction("Synthetic text", [], output_format="xlsx")

        self.assertEqual(summary["output_format"], "txt")
        self.assertEqual(summary["requested_output_format"], "xlsx")
        self.assertTrue(any("Unsupported output format" in item for item in warnings))


class AccessAnomalyEngineTests(unittest.TestCase):
    def test_flags_rapid_repeated_downloads(self):
        events = [_access_event("SYNTHETIC_ACTOR", "DOWNLOAD", 12, minute, "198.51.100.10") for minute in (0, 1, 2)]

        flags, alerts = detect_anomalies(events)

        self.assertTrue(all(flags[index]["rapid_repeated_downloads"] for index in range(3)))
        self.assertTrue(any(alert["flag"] == "rapid_repeated_downloads" for alert in alerts))

    def test_flags_new_ip_and_unusual_hour(self):
        events = [
            _access_event("SYNTHETIC_ACTOR", "VIEW", 12, 0, "198.51.100.20"),
            _access_event("SYNTHETIC_ACTOR", "VIEW", 22, 0, "198.51.100.21"),
        ]

        flags, alerts = detect_anomalies(events)

        self.assertTrue(flags[1]["new_ip_for_user"])
        self.assertTrue(flags[1]["unusual_hour"])
        self.assertTrue(any(alert["flag"] == "new_ip_for_user" for alert in alerts))
        self.assertTrue(any(alert["flag"] == "unusual_hour" for alert in alerts))

    def test_flags_high_volume_in_short_window(self):
        events = [_access_event("SYNTHETIC_ACTOR", "VIEW", 12, minute, "198.51.100.30") for minute in range(10)]

        flags, alerts = detect_anomalies(events)

        self.assertTrue(all(flags[index]["high_volume_in_short_window"] for index in range(10)))
        self.assertTrue(any(alert["flag"] == "high_volume_in_short_window" for alert in alerts))

    def test_benign_synthetic_activity_creates_no_alerts(self):
        events = [_access_event("SYNTHETIC_ACTOR", "VIEW", 12, minute, "198.51.100.40") for minute in (0, 5)]

        flags, alerts = detect_anomalies(events)

        self.assertEqual(alerts, [])
        for detail in flags.values():
            self.assertFalse(any(detail[name] for name in detail if name != "reasons"))


@override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
class SecureFindingHandlingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="SYNTHETIC ORG", slug="synthetic-org")
        cls.reviewer = User.objects.create_user(
            username="synth-reviewer",
            password="SyntheticPass123!",
            email="reviewer@example.invalid",
            role=User.Role.REVIEWER,
            organization=cls.organization,
        )
        cls.viewer = User.objects.create_user(
            username="synth-viewer",
            password="SyntheticPass123!",
            email="viewer@example.invalid",
            role=User.Role.VIEWER,
            organization=cls.organization,
        )
        cls.document = HealthcareDocument.objects.create(
            organization=cls.organization,
            uploaded_by=cls.viewer,
            title="Synthetic findings document",
            original_filename="synthetic.txt",
            file="",
            file_type=HealthcareDocument.FileType.TXT,
            sha256="0" * 64,
            text_extract="Synthetic SSN 000-00-0001",
            is_synthetic=True,
        )

    def _finding_payload(self):
        raw_value = "000-00-0001"
        text = self.document.text_extract
        return {
            "finding_type": "SSN",
            "category": "PHI",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "raw_value": raw_value,
            "start_offset": text.index(raw_value),
            "end_offset": text.index(raw_value) + len(raw_value),
        }

    def test_persist_findings_encrypts_raw_values_and_masks_context(self):
        raw_value = "000-00-0001"

        finding = persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)[0]

        self.assertTrue(finding.value_ciphertext)
        self.assertNotEqual(finding.value_ciphertext, raw_value)
        self.assertEqual(decrypt_secret(finding.value_ciphertext), raw_value)
        self.assertNotEqual(finding.value_masked, raw_value)
        self.assertNotIn(raw_value, finding.context_masked)
        self.assertEqual(finding.fingerprint, sha256_text(f"SSN|{raw_value.casefold()}"))

    def test_mask_for_review_denies_non_privileged_user(self):
        finding = persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)[0]

        result = mask_for_review(finding, self.viewer)

        self.assertFalse(result["authorized"])
        self.assertTrue(result["masked"])
        self.assertEqual(result["value"], "[REDACTED]")

    def test_mask_for_review_reveals_encrypted_value_to_privileged_user(self):
        finding = persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)[0]

        result = mask_for_review(finding, self.reviewer)

        self.assertTrue(result["authorized"])
        self.assertFalse(result["masked"])
        self.assertEqual(result["value"], "000-00-0001")

    def test_mask_for_review_reports_missing_encrypted_value(self):
        finding = persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)[0]
        finding.value_ciphertext = ""
        finding.save(update_fields=["value_ciphertext"])

        result = mask_for_review(finding, self.reviewer)

        self.assertTrue(result["masked"])
        self.assertEqual(result["value"], "[REDACTED]")
        self.assertIn("No encrypted value", result["reason"])

    def test_repeated_analysis_does_not_duplicate_findings_by_fingerprint(self):
        persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)
        persist_findings(self.document, [self._finding_payload()], created_by=self.viewer)

        self.assertEqual(SensitiveDataFinding.objects.filter(document=self.document).count(), 1)


class AnalysisServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="SYNTHETIC ANALYSIS ORG", slug="synthetic-analysis")
        cls.user = User.objects.create_user(
            username="synth-analyst",
            password="SyntheticPass123!",
            role=User.Role.ANALYST,
            organization=cls.organization,
        )
        cls.text = "Synthetic email synth.user@example.invalid"
        cls.document = HealthcareDocument.objects.create(
            organization=cls.organization,
            uploaded_by=cls.user,
            title="Synthetic analysis document",
            original_filename="synthetic.txt",
            file="",
            file_type=HealthcareDocument.FileType.TXT,
            sha256="1" * 64,
            text_extract=cls.text,
            is_synthetic=True,
        )

    @patch("analysis.services.detect_findings")
    def test_run_document_analysis_persists_findings_and_explainable_assessment(self, mocked_detect):
        email = "synth.user@example.invalid"
        finding = {
            "finding_type": "EMAIL",
            "category": "CONTACT",
            "severity": "HIGH",
            "confidence": 0.98,
            "raw_value": email,
            "start_offset": self.text.index(email),
            "end_offset": self.text.index(email) + len(email),
        }
        mocked_detect.return_value = ([finding], {"warnings": ["SYNTHETIC WARNING"]})

        result = run_document_analysis(self.document.pk)

        assessment = PrivacyAssessment.objects.get(document=self.document)
        self.assertEqual(result["findings_count"], 1)
        self.assertEqual(result["warnings"], ["SYNTHETIC WARNING"])
        self.assertGreater(result["risk_score"], 0)
        self.assertEqual(assessment.risk_score, result["risk_score"])
        self.assertTrue(assessment.indicators)
        self.assertTrue(assessment.recommendations)
        self.assertIn("Automated assessment", assessment.disclaimer)
        self.assertNotIn(email, str(assessment.findings_snapshot))
