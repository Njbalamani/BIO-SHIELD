from celery import shared_task

from accounts.models import User
from compliance.models import PrivacyAssessment
from documents.models import HealthcareDocument
from organizations.models import Organization
from reports.services import generate_pdf_report, render_report_pdf


@shared_task(bind=True, name="reports.pdf_report")
def pdf_report_task(
    self,
    report_id=None,
    organization_id=None,
    document_id=None,
    assessment_id=None,
    created_by_id=None,
    title="",
):
    if report_id:
        result = render_report_pdf(report_id)
        result["task_id"] = str(self.request.id or "")
        return result
    organization = Organization.objects.get(pk=organization_id)
    document = HealthcareDocument.objects.filter(pk=document_id).first() if document_id else None
    assessment = PrivacyAssessment.objects.filter(pk=assessment_id).first() if assessment_id else None
    created_by = User.objects.filter(pk=created_by_id).first() if created_by_id else None
    result = generate_pdf_report(
        organization,
        document=document,
        assessment=assessment,
        created_by=created_by,
        title=title,
    )
    result["task_id"] = str(self.request.id or "")
    return result
