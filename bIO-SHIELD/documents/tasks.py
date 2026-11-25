from celery import shared_task

from .services import (
    process_document,
    reanalyze_document,
    run_access_monitoring,
    run_anonymization_job,
)


@shared_task(bind=True, name="documents.process_document")
def process_document_task(self, document_id):
    result = process_document(document_id)
    result["task_id"] = str(self.request.id or "")
    return result


@shared_task(bind=True, name="documents.analyze_document")
def analyze_document_task(self, document_id, reviewer_id=None):
    from accounts.models import User

    reviewer = User.objects.filter(pk=reviewer_id).first() if reviewer_id else None
    result = reanalyze_document(document_id, reviewer=reviewer)
    result["task_id"] = str(self.request.id or "")
    return result


@shared_task(bind=True, name="documents.anonymization")
def anonymization_task(self, job_id):
    result = run_anonymization_job(job_id)
    result["task_id"] = str(self.request.id or "")
    return result


@shared_task(bind=True, name="documents.access_monitoring")
def access_monitoring_task(self, organization_id):
    result = run_access_monitoring(organization_id)
    result["task_id"] = str(self.request.id or "")
    return result
