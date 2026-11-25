from django.utils import timezone

from compliance.models import ComplianceChecklist, PrivacyAssessment
from documents.models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    HealthcareDocument,
    SensitiveDataFinding,
)
from organizations.services import organizations_for_user
from reports.models import Report


def _value_breakdown(queryset, field):
    counts = {}
    for value in queryset.values_list(field, flat=True):
        name = str(value or "UNKNOWN")
        counts[name] = counts.get(name, 0) + 1
    return counts


def _metrics_for_organizations(organizations):
    organizations = list(organizations)
    organization_ids = [organization.pk for organization in organizations]
    documents = HealthcareDocument.objects.filter(organization_id__in=organization_ids)
    findings = SensitiveDataFinding.objects.filter(organization_id__in=organization_ids)
    assessments = PrivacyAssessment.objects.filter(organization_id__in=organization_ids)
    checklists = ComplianceChecklist.objects.filter(organization_id__in=organization_ids)
    reports = Report.objects.filter(organization_id__in=organization_ids)
    alerts = AccessAlert.objects.filter(organization_id__in=organization_ids)
    events = AccessEvent.objects.filter(organization_id__in=organization_ids)
    jobs = AnonymizationJob.objects.filter(organization_id__in=organization_ids)
    scores = [int(value) for value in assessments.exclude(risk_score__isnull=True).values_list("risk_score", flat=True)]
    average_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
    return {
        "generated_at": timezone.now().isoformat(),
        "organizations": [
            {"id": str(organization.pk), "name": str(organization.name)} for organization in organizations
        ],
        "documents_total": documents.count(),
        "documents_completed": documents.filter(status=HealthcareDocument.Status.COMPLETED).count(),
        "documents_pending": documents.filter(status=HealthcareDocument.Status.PENDING).count(),
        "findings_total": findings.count(),
        "findings_by_severity": _value_breakdown(findings, "severity"),
        "findings_by_category": _value_breakdown(findings, "category"),
        "assessments_total": assessments.count(),
        "average_risk_score": average_risk,
        "checklists_total": checklists.count(),
        "checklists_completed": checklists.filter(status=ComplianceChecklist.Status.COMPLETED).count(),
        "reports_total": reports.count(),
        "alerts_total": alerts.count(),
        "alerts_open": alerts.filter(status=AccessAlert.Status.OPEN).count(),
        "access_events_total": events.count(),
        "anonymization_jobs_total": jobs.count(),
        "anonymization_jobs_completed": jobs.filter(status=AnonymizationJob.Status.COMPLETED).count(),
    }


def build_dashboard_metrics(user, organization_id=None):
    organizations = organizations_for_user(user)
    if organization_id is not None:
        organizations = [organization for organization in organizations if str(organization.pk) == str(organization_id)]
    return _metrics_for_organizations(organizations)


def get_dashboard_metrics(user):
    return build_dashboard_metrics(user)
