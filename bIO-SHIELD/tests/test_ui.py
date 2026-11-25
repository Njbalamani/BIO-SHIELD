from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import NoReverseMatch, reverse

from audit.models import AuditLog
from documents.models import HealthcareDocument, SensitiveDataFinding
from organizations.models import Organization


class BioShieldUISmokeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(
            name="Synthetic UI Org",
            slug="synthetic-ui-org",
            description="Synthetic organization for UI smoke tests.",
        )
        user_model = get_user_model()
        cls.user = user_model.objects.create_user(
            username="synthetic_ui_user",
            email="synthetic.ui.user@example.invalid",
            password="SyntheticPass123!",
            organization=cls.organization,
            role=getattr(user_model.Role, "VIEWER", "VIEWER"),
        )
        cls.forbidden_strings = [
            "Avery Placeholder",
            "Casey Testcase",
            "Sample Auditor",
            "Northwind Example Clinic",
            "patient@example.com",
            "SSN",
            "123-45-6789",
        ]
        cls.protected_routes = [
            "home",
            "dashboard:home",
            "documents:list",
            "documents:upload",
            "findings:list",
            "assessments:list",
            "anonymization:list",
            "access:list",
            "compliance:list",
            "reports:list",
            "organizations:list",
        ]
        cls.authenticated_routes = [
            "home",
            "dashboard:home",
            "documents:list",
            "documents:upload",
            "findings:list",
            "assessments:list",
            "anonymization:list",
            "access:list",
            "compliance:list",
            "reports:list",
            "organizations:list",
        ]

    def assertNoForbiddenStrings(self, content):
        for value in self.forbidden_strings:
            self.assertNotIn(value, content)

    def assertRedirectsToLogin(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        login_url = reverse("accounts:login")
        self.assertIn(login_url, response["Location"])

    def test_public_login_page_renders(self):
        response = self.client.get(reverse("accounts:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Welcome back")
        self.assertContains(response, "Sign in to your workspace")
        self.assertNoForbiddenStrings(response.content.decode("utf-8"))

    def test_public_register_page_renders(self):
        response = self.client.get(reverse("accounts:register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create your workspace")
        self.assertContains(response, "Register for the sandbox")
        self.assertNoForbiddenStrings(response.content.decode("utf-8"))

    def test_protected_html_pages_redirect_anonymous_users_to_login(self):
        for route_name in self.protected_routes:
            with self.subTest(route=route_name):
                self.assertRedirectsToLogin(reverse(route_name))

    def test_audit_list_redirects_anonymous_when_route_exists(self):
        try:
            url = reverse("audit:list")
        except NoReverseMatch:
            self.skipTest("audit:list route is not configured")
        self.assertRedirectsToLogin(url)

    def test_authenticated_synthetic_user_can_load_required_ui_routes(self):
        self.client.force_login(self.user)
        for route_name in self.authenticated_routes:
            with self.subTest(route=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                content = response.content.decode("utf-8")
                self.assertNoForbiddenStrings(content)
                self.assertIn("Synthetic data only", content)

    def test_authenticated_accounts_pages_load(self):
        self.client.force_login(self.user)
        for route_name, expected_text in [
            ("accounts:login", "Welcome back"),
            ("accounts:register", "Create your workspace"),
        ]:
            with self.subTest(route=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, expected_text)
                self.assertNoForbiddenStrings(response.content.decode("utf-8"))

    def test_audit_list_loads_for_authenticated_user_when_route_exists(self):
        try:
            url = reverse("audit:list")
        except NoReverseMatch:
            self.skipTest("audit:list route is not configured")
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertNoForbiddenStrings(content)
        self.assertIn("Synthetic data only", content)

    def test_compliance_disclaimer_text_appears_where_expected(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("compliance:list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This checklist is not a legal certification.")
        self.assertContains(
            response,
            "Automated checklists are decision support, not legal certification.",
        )

    def test_authenticated_home_and_dashboard_include_compliance_disclaimer_footer(self):
        self.client.force_login(self.user)
        for route_name in ["home", "dashboard:home"]:
            with self.subTest(route=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertContains(
                    response,
                    "Automated checklists are decision support, not legal certification.",
                )


class FindingReviewUITests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(
            name="Synthetic Review Org",
            slug="synthetic-review-org",
        )
        cls.other_organization = Organization.objects.create(
            name="Synthetic Outsider Org",
            slug="synthetic-outsider-org",
        )
        user_model = get_user_model()
        cls.viewer = user_model.objects.create_user(
            username="review_ui_viewer",
            email="review.ui.viewer@example.invalid",
            password="SyntheticPass123!",
            organization=cls.organization,
            role=user_model.Role.VIEWER,
        )
        cls.reviewer = user_model.objects.create_user(
            username="review_ui_reviewer",
            email="review.ui.reviewer@example.invalid",
            password="SyntheticPass123!",
            organization=cls.organization,
            role=user_model.Role.REVIEWER,
        )
        cls.outsider = user_model.objects.create_user(
            username="review_ui_outsider",
            email="review.ui.outsider@example.invalid",
            password="SyntheticPass123!",
            organization=cls.other_organization,
            role=user_model.Role.REVIEWER,
        )
        cls.document = HealthcareDocument.objects.create(
            organization=cls.organization,
            uploaded_by=cls.viewer,
            title="Synthetic review document",
            original_filename="synthetic_review.txt",
            file="",
            file_type=HealthcareDocument.FileType.TXT,
            sha256="0" * 64,
            text_extract="Synthetic review content.",
            status=HealthcareDocument.Status.COMPLETED,
            is_synthetic=True,
        )
        cls.finding = SensitiveDataFinding.objects.create(
            document=cls.document,
            organization=cls.organization,
            category=SensitiveDataFinding.Category.PII,
            finding_type="SYNTHETIC_EMAIL",
            value_masked="[REDACTED]",
            fingerprint="synthetic-review-fingerprint",
            confidence=0.91,
            methodology="synthetic-rule",
            severity=SensitiveDataFinding.Severity.MEDIUM,
        )

    def review_url(self):
        return reverse("findings:review", args=[self.finding.pk])

    def test_reviewer_can_record_decision_from_findings_list(self):
        self.client.force_login(self.reviewer)
        response = self.client.get(reverse("findings:list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.review_url())
        self.assertContains(response, "False positive")

        response = self.client.post(self.review_url(), {"status": "FALSE_POSITIVE"})
        self.assertRedirects(response, reverse("findings:list"))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, SensitiveDataFinding.Status.FALSE_POSITIVE)
        self.assertEqual(self.finding.reviewed_by, self.reviewer)
        self.assertIsNotNone(self.finding.reviewed_at)
        log = AuditLog.objects.get(action="FINDING_REVIEWED", target_id=str(self.finding.pk))
        self.assertEqual(log.metadata["status"], "FALSE_POSITIVE")
        self.assertFalse(log.metadata["revealed"])

    def test_viewer_cannot_review_and_does_not_see_review_controls(self):
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("findings:list"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.review_url())
        self.assertContains(response, "Read only")

        response = self.client.post(self.review_url(), {"status": "REMEDIATED"})
        self.assertEqual(response.status_code, 403)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, SensitiveDataFinding.Status.OPEN)
        self.assertIsNone(self.finding.reviewed_at)

    def test_review_cannot_target_another_organization(self):
        self.client.force_login(self.outsider)
        response = self.client.post(self.review_url(), {"status": "REVIEWED"})
        self.assertEqual(response.status_code, 404)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, SensitiveDataFinding.Status.OPEN)
