from django.db import transaction

from audit.services import audit
from compliance.models import ComplianceChecklist, PrivacyAssessment
from documents.services import first_value, update_row

DISCLAIMER = "Automated assessment is not legal certification."

_TEMPLATES = {
    "HIPAA_SECURITY": (
        (
            "ADM-01",
            "Administrative Safeguards",
            "Security official and workforce clearance processes are documented.",
            "ADMINISTRATIVE",
            10,
        ),
        (
            "ADM-02",
            "Security Awareness Training",
            "Workforce receives periodic privacy and security training.",
            "ADMINISTRATIVE",
            10,
        ),
        (
            "ADM-03",
            "Incident Response Plan",
            "A documented and tested incident response plan is in place.",
            "ADMINISTRATIVE",
            12,
        ),
        (
            "PHY-01",
            "Facility Access Controls",
            "Physical access to records and workstations is restricted.",
            "PHYSICAL",
            8,
        ),
        (
            "PHY-02",
            "Device and Media Controls",
            "Media disposal and device reuse procedures are documented.",
            "PHYSICAL",
            8,
        ),
        (
            "TEC-01",
            "Unique User Identification",
            "Each user has a unique account and access is reviewed.",
            "TECHNICAL",
            10,
        ),
        (
            "TEC-02",
            "Encryption at Rest and in Transit",
            "PHI is encrypted at rest and during transmission.",
            "TECHNICAL",
            14,
        ),
        (
            "TEC-03",
            "Audit Controls",
            "Access to PHI is logged and reviewed on a schedule.",
            "TECHNICAL",
            12,
        ),
        (
            "TEC-04",
            "Automatic Logoff",
            "Sessions terminate after a defined period of inactivity.",
            "TECHNICAL",
            6,
        ),
        (
            "ORG-01",
            "Business Associate Agreements",
            "Third-party agreements are current and accessible.",
            "ORGANIZATIONAL",
            10,
        ),
    ),
    "GDPR": (
        (
            "GDPR-01",
            "Lawful Basis",
            "A lawful basis is recorded for each processing activity.",
            "PRINCIPLES",
            12,
        ),
        (
            "GDPR-02",
            "Data Minimisation",
            "Only necessary personal data is collected and retained.",
            "PRINCIPLES",
            10,
        ),
        (
            "GDPR-03",
            "Data Subject Rights",
            "Procedures for access, correction, and erasure requests exist.",
            "RIGHTS",
            12,
        ),
        (
            "GDPR-04",
            "Breach Notification",
            "A breach notification workflow can meet the 72-hour deadline.",
            "ACCOUNTABILITY",
            12,
        ),
        (
            "GDPR-05",
            "Processor Agreements",
            "Processors are bound by written data processing agreements.",
            "ACCOUNTABILITY",
            10,
        ),
        (
            "GDPR-06",
            "Privacy by Design",
            "New systems are reviewed for privacy risks before deployment.",
            "ACCOUNTABILITY",
            8,
        ),
        (
            "GDPR-07",
            "International Transfers",
            "Cross-border transfers have an approved legal mechanism.",
            "TRANSFERS",
            8,
        ),
    ),
    "SOC2": (
        (
            "CC-01",
            "Control Environment",
            "Governance, ownership, and reporting lines are documented.",
            "COMMON_CRITERIA",
            10,
        ),
        (
            "CC-02",
            "Risk Assessment",
            "A recurring risk assessment is performed and tracked.",
            "COMMON_CRITERIA",
            12,
        ),
        (
            "CC-03",
            "Access Control",
            "Access is provisioned and revoked using approved procedures.",
            "COMMON_CRITERIA",
            12,
        ),
        (
            "CC-04",
            "System Operations",
            "Monitoring and backup procedures are documented.",
            "COMMON_CRITERIA",
            10,
        ),
        (
            "CC-05",
            "Confidentiality",
            "Confidential information is classified and protected.",
            "CONFIDENTIALITY",
            10,
        ),
    ),
}


def template_items(framework):
    key = str(framework or "HIPAA_SECURITY").upper()
    rows = _TEMPLATES.get(key, _TEMPLATES["HIPAA_SECURITY"])
    return [
        {
            "id": item_id,
            "title": title,
            "description": description,
            "category": category,
            "weight": weight,
            "required": True,
            "guidance": "Record an objective, evidence-based response before marking this item complete.",
        }
        for item_id, title, description, category, weight in rows
    ]


def _is_complete(value):
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in ("yes", "true", "implemented", "complete", "compliant", "1")


@transaction.atomic
def build_checklist(organization, framework="HIPAA_SECURITY", created_by=None, document=None):
    framework_name = str(framework or "HIPAA_SECURITY").upper()
    assessment = None
    if document is not None:
        assessment = PrivacyAssessment.objects.filter(document=document, organization=organization).first()
    checklist = ComplianceChecklist.objects.create(
        organization=organization,
        assessment=assessment,
        framework=framework_name,
        title=f"{framework_name.replace('_', ' ').title()} readiness checklist",
        items=template_items(framework_name),
        responses={},
        score=0,
        status=ComplianceChecklist.Status.DRAFT,
        created_by=created_by,
    )
    audit(
        None if created_by is None else created_by,
        organization,
        "CHECKLIST_CREATED",
        "ComplianceChecklist",
        str(checklist.pk),
        {"framework": framework_name, "item_count": len(checklist.items)},
        None,
    )
    return checklist


@transaction.atomic
def evaluate_checklist(checklist_id, responses, created_by=None):
    checklist = ComplianceChecklist.objects.get(pk=checklist_id)
    if not isinstance(responses, dict):
        responses = {}
    items = checklist.items if isinstance(checklist.items, list) else []
    total_weight = 0
    earned_weight = 0
    gaps = []
    completed = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = str(first_value(item, "id", "code", default=""))
        try:
            weight = float(first_value(item, "weight", default=1))
        except (TypeError, ValueError):
            weight = 1.0
        total_weight += weight
        if _is_complete(responses.get(item_id)):
            earned_weight += weight
            completed += 1
        else:
            gaps.append(item_id)
    score = int(round((earned_weight / total_weight) * 100)) if total_weight else 0
    update_row(
        checklist,
        responses=responses,
        score=max(0, min(100, score)),
        status=ComplianceChecklist.Status.COMPLETED,
    )
    audit(
        None if created_by is None else created_by,
        checklist.organization,
        "CHECKLIST_EVALUATED",
        "ComplianceChecklist",
        str(checklist.pk),
        {"score": checklist.score, "items_reviewed": len(items)},
        None,
    )
    return {
        "checklist_id": str(checklist.pk),
        "framework": checklist.framework,
        "score": checklist.score,
        "status": checklist.status,
        "items_total": len(items),
        "items_completed": completed,
        "gaps": gaps,
        "disclaimer": DISCLAIMER,
    }
