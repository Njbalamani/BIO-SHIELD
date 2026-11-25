from celery import shared_task

from accounts.models import User
from analysis.services import build_assessment, persist_assessment
from compliance.services import build_checklist, evaluate_checklist
from documents.models import HealthcareDocument


@shared_task(bind=True, name="compliance.assessment_task")
def assessment_task(self, document_id, created_by_id=None):
    document = HealthcareDocument.objects.get(pk=document_id)
    created_by = User.objects.filter(pk=created_by_id).first() if created_by_id else None
    data = build_assessment(document, created_by=created_by)
    assessment = persist_assessment(document, data, created_by=created_by)
    return {
        "task_id": str(self.request.id or ""),
        "document_id": str(document.pk),
        "assessment_id": str(assessment.pk),
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
    }


@shared_task(bind=True, name="compliance.checklist_task")
def checklist_task(
    self,
    organization_id,
    framework="HIPAA_SECURITY",
    created_by_id=None,
    document_id=None,
    responses=None,
):
    from organizations.models import Organization

    organization = Organization.objects.get(pk=organization_id)
    created_by = User.objects.filter(pk=created_by_id).first() if created_by_id else None
    document = HealthcareDocument.objects.filter(pk=document_id).first() if document_id else None
    checklist = build_checklist(organization, framework, created_by=created_by, document=document)
    result = {"task_id": str(self.request.id or ""), "checklist_id": str(checklist.pk)}
    if isinstance(responses, dict):
        result["evaluation"] = evaluate_checklist(checklist.pk, responses, created_by=created_by)
    return result
