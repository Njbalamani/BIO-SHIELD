import hashlib
import inspect
import io
import ipaddress
import json
import textwrap

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import FileField
from django.utils import timezone

from analysis.engines import mask_value, safe_preview, sha256_text
from analysis.engines.extraction import extract_text
from audit.models import AuditLog
from audit.services import audit
from documents.models import (
    AccessAlert,
    AccessEvent,
    AnonymizationJob,
    DocumentVersion,
    HealthcareDocument,
    SensitiveDataFinding,
)
from documents.validators import validate_document_upload
from organizations.models import Organization
from organizations.services import organization_for_user, organizations_for_user, require_role

_CATEGORY_ALIASES = {
    "CLINICAL": "MEDICAL",
    "FINANCIAL": "IDENTIFIER",
    "MODERATE": "MEDIUM",
}
_SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "WARNING": "MEDIUM"}
_ALLOWED_CATEGORIES = {"PII", "PHI", "CONTACT", "IDENTIFIER", "MEDICAL", "OTHER"}
_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ALLOWED_ACTIONS = {"VIEW", "DOWNLOAD", "API", "ANONYMIZED_DOWNLOAD"}
_ALLOWED_FORMATS = {"TXT", "DOCX", "PDF"}
_SENSITIVE_PARTS = ("raw", "value", "text", "content", "ciphertext", "token", "password", "secret")


def _model_fields(model):
    return {field.name: field for field in model._meta.fields}


def _prepared(model, values):
    fields = _model_fields(model)
    result = {}
    for key, value in values.items():
        field = fields.get(key)
        if field is None:
            continue
        if isinstance(value, (dict, list, tuple)) and field.get_internal_type() in ("CharField", "TextField"):
            value = json.dumps(value, sort_keys=True)
        result[key] = value
    return result


def create_row(model, **values):
    return model.objects.create(**_prepared(model, values))


def update_row(instance, **values):
    model = type(instance)
    fields = _model_fields(model)
    for key, value in _prepared(model, values).items():
        if (
            key in fields
            and not getattr(fields[key], "auto_now_add", False)
            and not getattr(fields[key], "auto_now", False)
        ):
            setattr(instance, key, value)
    instance.save()
    return instance


def call_engine(function, candidates=None, positional=None):
    candidates = candidates or {}
    positional = tuple(positional or ())
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        return function(*positional)
    accepted = {name: value for name, value in candidates.items() if name in parameters}
    required = [
        name
        for name, parameter in parameters.items()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    ]
    if accepted and (not required or all(name in accepted for name in required)):
        try:
            return function(**accepted)
        except TypeError:
            pass
    return function(*positional)


def first_value(data, *keys, default=""):
    if not isinstance(data, dict):
        return default
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def mask_secret(value):
    return mask_value(value, keep=0)


def mask_context(context, secret=""):
    text = safe_preview(str(context or ""), 0, 0) if context else ""
    if secret and str(context or ""):
        text = str(context).replace(str(secret), "[REDACTED]")
    return text or ""


def encrypt_secret(value):
    key = getattr(settings, "FIELD_ENCRYPTION_KEY", "")
    if not key or value is None or str(value) == "":
        return ""
    try:
        cipher = Fernet(key.encode() if isinstance(key, str) else key)
        return cipher.encrypt(str(value).encode("utf-8")).decode("ascii")
    except Exception:
        return ""


def decrypt_secret(ciphertext):
    key = getattr(settings, "FIELD_ENCRYPTION_KEY", "")
    if not key or not ciphertext:
        return ""
    try:
        cipher = Fernet(key.encode() if isinstance(key, str) else key)
        return cipher.decrypt(str(ciphertext).encode("ascii")).decode("utf-8")
    except Exception:
        return ""


def _valid_ip(value):
    try:
        ipaddress.ip_address(str(value or ""))
        return str(value)
    except ValueError:
        return None


def _client_ip(request):
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return _valid_ip(str(forwarded).split(",")[0].strip())
    return _valid_ip(request.META.get("REMOTE_ADDR", ""))


def _safe_metadata(metadata):
    clean = {}
    if not isinstance(metadata, dict):
        return clean
    for key, value in metadata.items():
        name = str(key).lower()
        if any(part in name for part in _SENSITIVE_PARTS):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[str(key)] = value
    return clean


def audit_event(
    user=None,
    action="",
    organization=None,
    document=None,
    detail="",
    request=None,
    metadata=None,
    target_type=None,
    target_id=None,
):
    safe = _safe_metadata(metadata)
    if detail:
        safe["detail"] = str(detail)[:200]
    resolved_target_type = str(target_type or (type(document).__name__ if document is not None else ""))[:100]
    resolved_target_id = str(target_id if target_id is not None else (document.pk if document is not None else ""))[
        :100
    ]
    try:
        return audit(
            user if getattr(user, "is_authenticated", False) else None,
            organization,
            action,
            resolved_target_type,
            resolved_target_id or None,
            safe,
            request,
        )
    except Exception:
        try:
            return create_row(
                AuditLog,
                user=user if getattr(user, "is_authenticated", False) else None,
                organization=organization,
                action=str(action)[:255],
                target_type=resolved_target_type,
                target_id=resolved_target_id or None,
                metadata=safe,
                ip_address=_client_ip(request),
            )
        except Exception:
            return None


def user_organizations(user):
    if not user or not getattr(user, "is_authenticated", False):
        return []
    if getattr(user, "is_superuser", False) or str(getattr(user, "role", "")).upper() == "ADMIN":
        return list(Organization.objects.all())
    return list(organizations_for_user(user))


def is_privileged(user, organization=None):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    try:
        require_role(user, "ADMIN", "REVIEWER")
        return True
    except Exception:
        return False


def resolve_organization(organization_id=None, user=None):
    if organization_id:
        if user is not None and not getattr(user, "is_superuser", False):
            return organization_for_user(user, organization_id)
        return Organization.objects.get(pk=organization_id)
    if user is not None:
        organizations = user_organizations(user)
        return organizations[0] if organizations else None
    return None


def attachment_field(model, names):
    fields = _model_fields(model)
    for name in names:
        if isinstance(fields.get(name), FileField):
            return name
    for name, field in fields.items():
        if isinstance(field, FileField):
            return name
    return ""


def document_bytes(document):
    field_file = getattr(document, "file", None)
    if field_file is not None and hasattr(field_file, "read"):
        try:
            data = field_file.read()
            field_file.seek(0)
            if data:
                return bytes(data)
        except Exception:
            pass
    text = getattr(document, "text_extract", "")
    return str(text).encode("utf-8") if text else b""


def document_text(document):
    return str(getattr(document, "text_extract", "") or "")


def document_name(document):
    return str(getattr(document, "original_filename", "") or getattr(document, "title", "") or "document.txt")


def document_extension(document):
    name = document_name(document).lower()
    for extension in (".txt", ".pdf", ".docx"):
        if name.endswith(extension):
            return extension
    file_type = str(getattr(document, "file_type", "") or "").lower()
    return f".{file_type}" if file_type else ".txt"


def hash_bytes(payload):
    return hashlib.sha256(payload or b"").hexdigest()


def pdf_bytes(text, title):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(title or "BioShield Report")
    pdf.setFont("Helvetica", 11)
    y_position = 750
    for line in textwrap.wrap(str(text or ""), 95) or [""]:
        pdf.drawString(72, y_position, line[:110])
        y_position -= 16
        if y_position < 72:
            pdf.showPage()
            y_position = 750
            pdf.setFont("Helvetica", 11)
    pdf.save()
    payload = buffer.getvalue()
    return payload if payload.startswith(b"%PDF") else b"%PDF-1.4\n%%EOF\n"


def normalize_findings(result):
    if isinstance(result, tuple) and result:
        result = result[0]
    if isinstance(result, dict):
        items = first_value(result, "findings", "items", "results", "detections", default=[])
    elif isinstance(result, (list, tuple)):
        items = result
    else:
        items = []
    if isinstance(items, dict):
        items = list(items.values())
    return [item if isinstance(item, dict) else {"value": str(item)} for item in items]


def normalize_anomalies(result):
    if isinstance(result, tuple) and len(result) > 1 and isinstance(result[1], (list, tuple)):
        result = result[1]
    elif isinstance(result, tuple) and result:
        result = result[0]
    if isinstance(result, dict):
        items = first_value(result, "anomalies", "alerts", "results", "items", default=[])
    elif isinstance(result, (list, tuple)):
        items = result
    else:
        items = []
    if isinstance(items, dict):
        items = list(items.values())
    normalized = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(item)
        else:
            normalized.append({"reason": str(item), "severity": "MEDIUM"})
    return normalized


def save_attachment(instance, names, filename, payload):
    name = attachment_field(type(instance), names)
    if not name or not payload:
        return ""
    getattr(instance, name).save(filename or "attachment.bin", ContentFile(payload), save=True)
    return name


@transaction.atomic
def create_document_from_upload(upload, organization, created_by=None, filename="", **extra):
    raw_bytes = b""
    if upload is not None and hasattr(upload, "read"):
        raw_bytes = upload.read()
        upload.seek(0)
    elif isinstance(upload, (bytes, bytearray)):
        raw_bytes = bytes(upload)
    name = filename or getattr(upload, "name", "") or "document.txt"
    digest = hash_bytes(raw_bytes)
    extension = ""
    for suffix in (".txt", ".pdf", ".docx"):
        if name.lower().endswith(suffix):
            extension = suffix.lstrip(".").upper()
            break
    values = {
        "organization": organization,
        "uploaded_by": created_by,
        "title": extra.pop("title", "") or name,
        "original_filename": name,
        "file_type": extension or "TXT",
        "sha256": digest,
        "size_bytes": len(raw_bytes),
        "status": HealthcareDocument.Status.PENDING,
        "is_synthetic": bool(extra.pop("is_synthetic", True)),
    }
    values.update(extra)
    document = create_row(HealthcareDocument, **values)
    save_attachment(document, ("file",), name, raw_bytes)
    return document


@transaction.atomic
def process_document(document_id):
    document = HealthcareDocument.objects.get(pk=document_id)
    field_file = document.file
    max_bytes = int(getattr(settings, "MAX_UPLOAD_SIZE_MB", 10)) * 1024 * 1024
    try:
        field_file.open("rb")
        validated_bytes, extension, digest = validate_document_upload(field_file, max_bytes)
    finally:
        field_file.close()
    extracted = extract_text(validated_bytes, extension.lstrip("."))
    if isinstance(extracted, tuple) and extracted:
        text = extracted[0]
        metadata = extracted[1] if len(extracted) > 1 else {}
    else:
        text = extracted
        metadata = {}
    update_row(
        document,
        title=document.title or document_name(document),
        file_type=extension.upper(),
        sha256=digest,
        size_bytes=len(validated_bytes),
        text_extract=str(text or ""),
        status=HealthcareDocument.Status.COMPLETED,
        last_analyzed_at=timezone.now(),
    )
    from analysis.services import run_document_analysis

    analysis_result = run_document_analysis(document.pk)
    audit_event(
        user=getattr(document, "uploaded_by", None),
        action="DOCUMENT_PROCESSED",
        organization=document.organization,
        document=document,
        detail=f"Processed document {document.pk}",
        metadata={"char_count": len(str(text or "")), "page_count": first_value(metadata, "page_count", default=0)},
    )
    return {
        "document_id": str(document.pk),
        "status": "completed",
        "sha256": digest,
        "text_length": len(str(text or "")),
        "findings_count": analysis_result.get("findings_count", 0),
        "risk_score": analysis_result.get("risk_score", 0),
        "warnings": analysis_result.get("warnings", []),
    }


@transaction.atomic
def reanalyze_document(document_id, reviewer=None):
    document = HealthcareDocument.objects.get(pk=document_id)
    from analysis.services import run_document_analysis

    result = run_document_analysis(document.pk)
    update_row(document, status=HealthcareDocument.Status.COMPLETED, last_analyzed_at=timezone.now())
    audit_event(
        user=reviewer,
        action="DOCUMENT_REANALYZED",
        organization=document.organization,
        document=document,
        detail=f"Reanalyzed document {document.pk}",
    )
    result["reviewer_id"] = str(reviewer.pk) if reviewer else ""
    return result


@transaction.atomic
def persist_findings(document, findings, created_by=None):
    saved = []
    fields = _model_fields(SensitiveDataFinding)
    for item in normalize_findings(findings):
        raw_value = first_value(item, "raw_value", "value", "raw", "matched_text", "text", "sensitive_value", "match")
        finding_type = str(
            first_value(item, "finding_type", "type", "category", "label", "kind", default="SENSITIVE_DATA")
        )[:100]
        category = str(first_value(item, "category", "label", default="OTHER")).upper()
        category = _CATEGORY_ALIASES.get(category, category)
        if category not in _ALLOWED_CATEGORIES:
            category = "OTHER"
        severity = str(first_value(item, "severity", "risk", "risk_level", default="LOW")).upper()
        severity = _SEVERITY_ALIASES.get(severity, severity)
        if severity not in _ALLOWED_SEVERITIES:
            severity = "LOW"
        start = first_value(item, "start_offset", "start", "begin", "position", default=None)
        end = first_value(item, "end_offset", "end", "finish", default=None)
        try:
            start = int(start) if start is not None else None
        except (TypeError, ValueError):
            start = None
        try:
            end = int(end) if end is not None else None
        except (TypeError, ValueError):
            end = None
        ciphertext = encrypt_secret(raw_value)
        masked = str(first_value(item, "value_masked", "masked_value", "preview", default="")) or mask_secret(raw_value)
        context = str(first_value(item, "context_masked", "context", "surrounding_text", "snippet", default=""))
        if not context:
            context = safe_preview(document_text(document), start or 0, end or (start or 0) + len(str(raw_value or "")))
        fingerprint = str(first_value(item, "fingerprint", "hash", default="")) or sha256_text(
            f"{finding_type}|{str(raw_value or '').casefold()}"
        )
        values = {
            "document": document,
            "organization": document.organization,
            "category": category,
            "finding_type": finding_type,
            "value_masked": masked[:255],
            "value_ciphertext": ciphertext,
            "fingerprint": fingerprint[:128],
            "confidence": first_value(item, "confidence", "score", "probability", default=0.0),
            "methodology": str(first_value(item, "methodology", "methodologies", default=""))[:100],
            "line_number": first_value(item, "line_number", default=None),
            "start_offset": start,
            "end_offset": end,
            "context_masked": context,
            "severity": severity,
            "status": SensitiveDataFinding.Status.OPEN,
            "raw": {},
        }
        lookup = {"document": document, "fingerprint": values["fingerprint"], "finding_type": finding_type}
        if not all(key in fields for key in lookup):
            finding = create_row(SensitiveDataFinding, **values)
        else:
            finding, _ = SensitiveDataFinding.objects.update_or_create(defaults=values, **lookup)
        saved.append(finding)
    return saved


@transaction.atomic
def create_document_version(document, raw_bytes, filename, created_by, note=""):
    payload = bytes(raw_bytes or b"")
    number = DocumentVersion.objects.filter(document=document).count() + 1
    name = filename or document_name(document)
    version = create_row(
        DocumentVersion,
        document=document,
        version_number=number,
        sha256=hash_bytes(payload),
        filename=name,
        created_by=created_by,
        change_note=str(note or "")[:1000],
    )
    save_attachment(version, ("file",), name, payload)
    return version


@transaction.atomic
def create_anonymization_job(document, rules, output_format, created_by):
    output = str(output_format or "TXT").upper()
    if output not in _ALLOWED_FORMATS:
        output = "TXT"
    return create_row(
        AnonymizationJob,
        document=document,
        organization=document.organization,
        created_by=created_by,
        status=AnonymizationJob.Status.PENDING,
        replacement_rules=rules or {},
        output_format=output,
        summary={},
        warnings=[],
    )


def _redaction_payload(result, output_format):
    if isinstance(result, dict):
        payload = first_value(result, "bytes", "data", "content", "output", "redacted_bytes", "pdf", "text", default="")
    else:
        payload = result
    if isinstance(payload, (bytes, bytearray)):
        payload = bytes(payload)
    else:
        payload = str(payload or "").encode("utf-8")
    if output_format == "PDF" and not payload.startswith(b"%PDF"):
        payload = pdf_bytes(payload.decode("utf-8", errors="replace"), "BioShield Anonymized Document")
    if output_format == "DOCX" and not payload.startswith(b"PK"):
        payload = payload
    return payload


@transaction.atomic
def run_anonymization_job(job_id):
    job = AnonymizationJob.objects.get(pk=job_id)
    document = job.document
    rules = job.replacement_rules or {}
    output_format = str(job.output_format or "TXT").upper()
    text = document_text(document)
    from analysis.engines.anonymization import apply_redaction

    findings = list(SensitiveDataFinding.objects.filter(document=document))
    sanitized, summary, warnings = apply_redaction(text, findings, rules=rules, output_format=output_format.lower())
    result = {"text": sanitized, "summary": summary, "warnings": warnings}
    payload = _redaction_payload(result, output_format)
    extension = output_format.lower() if output_format.isalpha() else "txt"
    filename = f"anonymized-{document.pk}.{extension}"
    save_attachment(job, ("output_file",), filename, payload)
    if isinstance(result, dict):
        summary = first_value(result, "summary", "statistics", default={})
        warnings = first_value(result, "warnings", default=[])
    else:
        summary = {}
        warnings = []
    update_row(
        job,
        status=AnonymizationJob.Status.COMPLETED,
        finished_at=timezone.now(),
        summary=summary if isinstance(summary, dict) else {"detail": str(summary)[:200]},
        warnings=warnings if isinstance(warnings, list) else [str(warnings)[:200]],
    )
    audit_event(
        user=job.created_by,
        action="ANONYMIZATION_COMPLETED",
        organization=job.organization,
        document=document,
        detail=f"Completed anonymization job {job.pk}",
        target_type="AnonymizationJob",
        target_id=str(job.pk),
    )
    return {
        "job_id": str(job.pk),
        "status": "completed",
        "output_format": output_format,
        "filename": filename,
        "bytes": len(payload),
    }


@transaction.atomic
def record_access_event(document, user=None, action="VIEW", request=None, actor_label=""):
    action_name = str(action or "VIEW").upper()
    if action_name not in _ALLOWED_ACTIONS:
        action_name = "API"
    actor = actor_label or getattr(user, "email", "") or getattr(user, "username", "") or "ANONYMOUS"
    return create_row(
        AccessEvent,
        document=document,
        organization=document.organization,
        user=user if getattr(user, "is_authenticated", False) else None,
        actor_label=str(actor)[:255],
        action=action_name,
        ip_address=_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:2000] if request is not None else "",
        metadata={"source": "api", "actor": str(actor)[:120]},
    )


def _normalize_alert_severity(value):
    severity = str(value or "MEDIUM").upper()
    if severity in _SEVERITY_ALIASES:
        severity = _SEVERITY_ALIASES[severity]
    return severity if severity in _ALLOWED_SEVERITIES else "MEDIUM"


@transaction.atomic
def run_access_monitoring(organization_id):
    organization = Organization.objects.get(pk=organization_id)
    events = list(AccessEvent.objects.filter(organization=organization).select_related("document")[:500])
    from analysis.engines.access import detect_anomalies

    result = detect_anomalies(events)
    anomalies = normalize_anomalies(result)
    alerts = []
    for item in anomalies:
        event = first_value(item, "event", "access_event", "event_id", default=None)
        if event is None:
            indices = first_value(item, "event_indices", default=[])
            if indices and 0 <= int(indices[0]) < len(events):
                event = events[int(indices[0])]
        if event is not None and not hasattr(event, "pk"):
            try:
                event = AccessEvent.objects.get(pk=int(event), organization=organization)
            except (AccessEvent.DoesNotExist, TypeError, ValueError):
                event = None
        reason = str(
            first_value(item, "reason", "description", "message", "detail", "anomaly", default="ANOMALOUS_ACCESS")
        )[:2000]
        alert = create_row(
            AccessAlert,
            organization=organization,
            event=event,
            severity=_normalize_alert_severity(first_value(item, "severity", "risk_level", default="MEDIUM")),
            title=str(first_value(item, "title", "label", default="Anomalous access detected"))[:255],
            reason=reason,
            status=AccessAlert.Status.OPEN,
        )
        alerts.append(alert)
        indices = first_value(item, "event_indices", default=[])
        affected = []
        if indices:
            for index in indices:
                try:
                    position = int(index)
                except (TypeError, ValueError):
                    continue
                if 0 <= position < len(events):
                    affected.append(events[position])
        elif event is not None:
            affected.append(event)
        for affected_event in affected:
            update_row(affected_event, anomaly_flag=True, anomaly_reason=reason[:500])
    create_row(
        AuditLog,
        action="ACCESS_MONITORING_COMPLETED",
        target_type="Organization",
        target_id=str(organization.pk),
        metadata={"events_checked": len(events), "alerts_created": len(alerts)},
    )
    return {
        "organization_id": str(organization_id),
        "events_checked": len(events),
        "alerts_created": len(alerts),
        "alert_ids": [str(alert.pk) for alert in alerts],
    }


@transaction.atomic
def build_synthetic_events(organization, document, count=40):
    events = []
    actions = ("VIEW", "DOWNLOAD", "VIEW", "API", "ANONYMIZED_DOWNLOAD")
    for index in range(max(0, int(count))):
        label = f"SYNTHETIC_ACTOR_{(index % 6) + 1}"
        events.append(
            create_row(
                AccessEvent,
                document=document,
                organization=organization,
                actor_label=label,
                action=actions[index % len(actions)],
                ip_address=f"198.51.100.{(index % 254) + 1}",
                user_agent="BioShieldSyntheticMonitor/1.0",
                metadata={"synthetic": True, "actor": label, "sequence": index},
            )
        )
    return events
