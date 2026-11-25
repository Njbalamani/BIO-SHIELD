from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from analysis.engines import safe_settings
from analysis.engines.detection import detect_findings
from analysis.engines.risk import calculate_privacy_risk
from compliance.models import PrivacyAssessment
from documents.models import AccessEvent, HealthcareDocument, SensitiveDataFinding
from documents.services import (
    audit_event,
    decrypt_secret,
    document_text,
    first_value,
    is_privileged,
)

DISCLAIMER = "Automated assessment is not legal certification."


def _snapshot(findings):
    snapshot = []
    for finding in findings:
        if isinstance(finding, dict):
            snapshot.append(
                {
                    "finding_type": str(first_value(finding, "finding_type", "type", default="SENSITIVE_DATA"))[:100],
                    "category": str(first_value(finding, "category", default="OTHER"))[:20],
                    "severity": str(first_value(finding, "severity", default="LOW"))[:20],
                    "value_masked": str(first_value(finding, "value_masked", "masked", default="[REDACTED]"))[:255],
                    "fingerprint": str(first_value(finding, "fingerprint", default=""))[:128],
                }
            )
        else:
            snapshot.append(
                {
                    "finding_type": str(getattr(finding, "finding_type", "SENSITIVE_DATA"))[:100],
                    "category": str(getattr(finding, "category", "OTHER"))[:20],
                    "severity": str(getattr(finding, "severity", "LOW"))[:20],
                    "value_masked": str(getattr(finding, "value_masked", "[REDACTED]"))[:255],
                    "fingerprint": str(getattr(finding, "fingerprint", ""))[:128],
                }
            )
    return snapshot


def _risk_tuple(result, findings):
    if isinstance(result, (list, tuple)) and len(result) >= 4:
        score, level, indicators, recommendations = result[:4]
    else:
        score = first_value(result, "risk_score", "score", default=0)
        level = first_value(result, "risk_level", "level", default="LOW")
        indicators = first_value(result, "indicators", default=[])
        recommendations = first_value(result, "recommendations", default=[])
    try:
        score = int(round(float(score)))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(255, score))
    level = str(level or "LOW").upper()
    if level not in ("LOW", "MODERATE", "HIGH", "CRITICAL"):
        level = "LOW" if score < 20 else "MODERATE" if score < 45 else "HIGH" if score < 75 else "CRITICAL"
    if not isinstance(indicators, list):
        indicators = [{"name": "indicators", "value": indicators, "detail": "Risk indicators."}]
    if not isinstance(recommendations, list):
        recommendations = [str(recommendations)]
    return score, level, indicators, recommendations


@transaction.atomic
def run_document_analysis(document_id):
    document = HealthcareDocument.objects.get(pk=document_id)
    text = document_text(document)
    findings, summary = detect_findings(text, source_name=f"document-{document.pk}")
    from documents.services import persist_findings

    saved = persist_findings(document, findings, created_by=getattr(document, "uploaded_by", None))
    access_events = list(AccessEvent.objects.filter(document=document))
    score, level, indicators, recommendations = _risk_tuple(
        calculate_privacy_risk(findings, access_events=access_events), findings
    )
    assessment_data = {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "recommendations": recommendations,
        "findings_snapshot": _snapshot(saved),
        "disclaimer": DISCLAIMER,
        "summary": summary,
    }
    assessment = persist_assessment(document, assessment_data, created_by=getattr(document, "uploaded_by", None))
    audit_event(
        user=getattr(document, "uploaded_by", None),
        action="DOCUMENT_ANALYZED",
        organization=document.organization,
        document=document,
        detail=f"Analyzed document {document.pk}",
        target_type="PrivacyAssessment",
        target_id=str(assessment.pk),
        metadata={"findings_count": len(saved), "risk_score": score, "risk_level": level},
    )
    return {
        "document_id": str(document.pk),
        "assessment_id": str(assessment.pk),
        "findings_count": len(saved),
        "risk_score": score,
        "risk_level": level,
        "warnings": list(first_value(summary, "warnings", default=[])),
        "assessment": assessment_data,
    }


def ai_status():
    configured = safe_settings()
    encryption_ready = bool(getattr(settings, "FIELD_ENCRYPTION_KEY", ""))
    return {
        "status": "operational",
        "provider": "local",
        "model_path": str(getattr(settings, "AI_MODEL_PATH", "") or ""),
        "risk_model_path": str(getattr(settings, "RISK_MODEL_PATH", "") or ""),
        "risk_model_available": Path(str(getattr(configured, "RISK_MODEL_PATH", "") or "")).exists(),
        "encryption_enabled": encryption_ready,
        "synthetic_data_only": bool(getattr(settings, "SYNTHETIC_DATA_ONLY", True)),
        "engines": {
            "extraction": True,
            "detection": True,
            "risk": True,
            "anonymization": True,
            "access_monitoring": True,
        },
        "detection_options": {
            "presidio": bool(getattr(configured, "ENABLE_PRESIDIO", False)),
            "spacy": bool(getattr(configured, "ENABLE_SPACY_MODEL", True)),
        },
        "disclaimer": DISCLAIMER,
    }


def mask_for_review(finding, user):
    organization = getattr(finding, "organization", None)
    authorized = is_privileged(user, organization)
    result = {
        "finding_id": str(getattr(finding, "pk", "")),
        "finding_type": str(getattr(finding, "finding_type", "")),
        "value": "[REDACTED]",
        "masked": True,
        "authorized": authorized,
    }
    if not authorized:
        return result
    plaintext = decrypt_secret(getattr(finding, "value_ciphertext", ""))
    if not plaintext:
        result["reason"] = "No encrypted value is available for this finding."
        return result
    result["value"] = plaintext
    result["masked"] = False
    return result


def review_finding(finding, user, decision=None, request=None, reveal=True):
    if reveal:
        result = mask_for_review(finding, user)
    else:
        result = {
            "finding_id": str(getattr(finding, "pk", "")),
            "finding_type": str(getattr(finding, "finding_type", "")),
            "value": "[REDACTED]",
            "masked": True,
            "authorized": is_privileged(user, getattr(finding, "organization", None)),
        }
    if not result["authorized"]:
        return None
    status_value = str(decision or SensitiveDataFinding.Status.REVIEWED).upper()
    if status_value not in SensitiveDataFinding.Status.values:
        status_value = SensitiveDataFinding.Status.REVIEWED
    finding.status = status_value
    finding.reviewed_by = user
    finding.reviewed_at = timezone.now()
    finding.save(update_fields=["status", "reviewed_by", "reviewed_at"])
    result["status"] = status_value
    audit_event(
        user=user,
        action="FINDING_REVIEWED",
        organization=finding.organization,
        document=finding.document,
        detail=f"Reviewed finding {finding.pk}",
        request=request,
        target_type="SensitiveDataFinding",
        target_id=str(finding.pk),
        metadata={"status": status_value, "revealed": bool(not result["masked"])},
    )
    return result


def build_assessment(document, created_by=None, access_events=None):
    findings = list(SensitiveDataFinding.objects.filter(document=document))
    if access_events is None:
        access_events = list(AccessEvent.objects.filter(document=document))
    elif not isinstance(access_events, (list, tuple)):
        access_events = list(access_events)
    score, level, indicators, recommendations = _risk_tuple(
        calculate_privacy_risk(findings, access_events=access_events), findings
    )
    severity_counts = {}
    for finding in findings:
        severity = str(finding.severity)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "document_id": str(document.pk),
        "organization_id": str(getattr(document, "organization_id", "") or ""),
        "created_by_id": str(getattr(created_by, "pk", "") or ""),
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "recommendations": recommendations,
        "findings_snapshot": _snapshot(findings),
        "findings_count": len(findings),
        "severity_counts": severity_counts,
        "access_events_count": len(access_events),
        "disclaimer": DISCLAIMER,
        "generated_at": timezone.now().isoformat(),
    }


@transaction.atomic
def persist_assessment(document, assessment_data, created_by=None):
    data = dict(assessment_data or {})
    score, level, indicators, recommendations = _risk_tuple(
        (
            data.get("risk_score", 0),
            data.get("risk_level", "LOW"),
            data.get("indicators", []),
            data.get("recommendations", []),
        ),
        [],
    )
    values = {
        "document": document,
        "organization": document.organization,
        "created_by": created_by,
        "assessor_type": data.get("assessor_type", PrivacyAssessment.AssessorType.AUTOMATED),
        "status": data.get("status", PrivacyAssessment.Status.COMPLETED),
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "recommendations": recommendations,
        "findings_snapshot": _snapshot(data.get("findings_snapshot", [])),
        "disclaimer": str(data.get("disclaimer", DISCLAIMER))[:2000],
    }
    assessment, _ = PrivacyAssessment.objects.update_or_create(
        document=document,
        organization=document.organization,
        defaults=values,
    )
    return assessment
