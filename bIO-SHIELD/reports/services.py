import hashlib
import io
from xml.sax.saxutils import escape

from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from audit.services import audit
from compliance.models import ComplianceChecklist, PrivacyAssessment
from documents.models import (
    AccessAlert,
    AnonymizationJob,
    HealthcareDocument,
    SensitiveDataFinding,
)
from documents.services import audit_event, update_row
from reports.models import Report

DISCLAIMER = "Automated assessment is not legal certification."


def build_report_summary(organization, document=None, assessment=None):
    documents = HealthcareDocument.objects.filter(organization=organization)
    if document is not None:
        documents = documents.filter(pk=document.pk)
    findings = SensitiveDataFinding.objects.filter(organization=organization)
    alerts = AccessAlert.objects.filter(organization=organization)
    jobs = AnonymizationJob.objects.filter(organization=organization)
    assessments = PrivacyAssessment.objects.filter(organization=organization)
    checklists = ComplianceChecklist.objects.filter(organization=organization)
    if document is not None:
        findings = findings.filter(document=document)
        jobs = jobs.filter(document=document)
        assessments = assessments.filter(document=document)
    if assessment is not None:
        assessments = assessments.filter(pk=assessment.pk)
    severity_counts = {}
    for finding in findings:
        severity = str(finding.severity)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    risk_scores = [int(item.risk_score) for item in assessments]
    average_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
    return {
        "organization": str(getattr(organization, "name", "")),
        "document_title": str(getattr(document, "title", "")) if document is not None else "",
        "assessment_id": str(getattr(assessment, "pk", "")) if assessment is not None else "",
        "documents_total": documents.count(),
        "findings_total": findings.count(),
        "severity_counts": severity_counts,
        "assessments_total": assessments.count(),
        "average_risk_score": average_risk,
        "open_alerts": alerts.filter(status=AccessAlert.Status.OPEN).count(),
        "alerts_total": alerts.count(),
        "anonymization_jobs_total": jobs.count(),
        "checklists_total": checklists.count(),
        "disclaimer": DISCLAIMER,
    }


@transaction.atomic
def generate_pdf_report(organization, document=None, assessment=None, created_by=None, title=""):
    summary = build_report_summary(organization, document=document, assessment=assessment)
    report_title = str(title or "BioShield Privacy Assessment Report")[:255]
    report = Report.objects.create(
        organization=organization,
        document=document,
        assessment=assessment,
        created_by=created_by,
        report_type="PRIVACY_ASSESSMENT",
        format=Report.Format.PDF,
        title=report_title,
        summary=summary,
    )
    result = render_report_pdf(report.pk)
    audit(
        None if created_by is None else created_by,
        organization,
        "REPORT_GENERATED",
        "Report",
        str(report.pk),
        {"title": report_title[:120], "document_id": str(getattr(document, "pk", "") or "")},
        None,
    )
    result["report_id"] = str(report.pk)
    result["summary"] = summary
    return result


@transaction.atomic
def render_report_pdf(report_id):
    report = Report.objects.get(pk=report_id)
    summary = report.summary if isinstance(report.summary, dict) else build_report_summary(report.organization)
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=escape(str(report.title or "BioShield Report"))[:200],
        author="BioShield",
        subject="Automated privacy assessment",
    )
    story = [
        Paragraph(escape(str(report.title or "BioShield Privacy Report")), styles["Title"]),
        Paragraph(f"Organization: {escape(str(getattr(report.organization, 'name', '')))}", styles["Normal"]),
        Paragraph(f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 18),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            "This report summarizes automated privacy indicators recorded in the BioShield system. "
            "It is intended for internal review and remediation planning.",
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]
    rows = [
        ["Metric", "Value"],
        ["Documents reviewed", str(summary.get("documents_total", 0))],
        ["Sensitive findings", str(summary.get("findings_total", 0))],
        ["Average risk score", str(summary.get("average_risk_score", 0))],
        ["Open access alerts", str(summary.get("open_alerts", 0))],
        ["Anonymization jobs", str(summary.get("anonymization_jobs_total", 0))],
        ["Checklists", str(summary.get("checklists_total", 0))],
    ]
    table = Table(rows, colWidths=[230, 230])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([table, Spacer(1, 18), Paragraph("Disclaimer", styles["Heading2"])])
    story.append(Paragraph(escape(DISCLAIMER), styles["Normal"]))
    story.append(
        Paragraph(
            "Findings are redacted in this report. Refer to the review workflow for "
            "authorized access to encrypted values.",
            styles["Normal"],
        )
    )
    document.build(story)
    payload = buffer.getvalue()
    if not payload.startswith(b"%PDF"):
        from reportlab.pdfgen import canvas

        fallback = io.BytesIO()
        pdf = canvas.Canvas(fallback, pagesize=letter)
        pdf.setTitle("BioShield Report")
        pdf.drawString(72, 750, "BioShield Privacy Report")
        pdf.drawString(72, 730, DISCLAIMER)
        pdf.save()
        payload = fallback.getvalue()
    filename = f"report-{report.pk}.pdf"
    report.file.save(filename, ContentFile(payload), save=True)
    update_row(report, report_type=report.report_type or "PRIVACY_ASSESSMENT", format=Report.Format.PDF)
    audit_event(
        action="REPORT_RENDERED",
        organization=report.organization,
        document=report.document,
        detail=f"Rendered report {report.pk}",
        target_type="Report",
        target_id=str(report.pk),
        metadata={"sha256": hashlib.sha256(payload).hexdigest()},
    )
    return {
        "report_id": str(report.pk),
        "filename": filename,
        "bytes": len(payload),
        "is_pdf": payload.startswith(b"%PDF"),
        "disclaimer": DISCLAIMER,
        "media_url": f"{getattr(settings, 'MEDIA_URL', '/media/')}{report.file.name}",
    }
