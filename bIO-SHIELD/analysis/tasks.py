from celery import shared_task

from .services import run_document_analysis


@shared_task(bind=True, name="analysis.analyze_document")
def analyze_document_task(self, document_id):
    result = run_document_analysis(document_id)
    result["task_id"] = str(self.request.id or "")
    return result
