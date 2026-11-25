from .models import AuditLog

SENSITIVE_KEY_PARTS = (
    "text",
    "content",
    "value",
    "raw",
    "ciphertext",
    "token",
    "password",
    "secret",
    "extract",
    "body",
)


def _sanitize_metadata(metadata):
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        return {}
    clean = {}
    for key, value in metadata.items():
        name = str(key).lower()
        if any(part in name for part in SENSITIVE_KEY_PARTS):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[str(key)] = value
        elif isinstance(value, dict):
            clean[str(key)] = _sanitize_metadata(value)
        elif isinstance(value, (list, tuple)):
            clean[str(key)] = [
                _sanitize_metadata(item)
                if isinstance(item, dict)
                else item
                if isinstance(item, (str, int, float, bool)) or item is None
                else None
                for item in value
            ]
    return clean


def _client_ip(request):
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate[:45]
    remote = request.META.get("REMOTE_ADDR", "")
    return remote[:45] or None


def audit(user, organization, action, target_type="", target_id=None, metadata=None, request=None):
    return AuditLog.objects.create(
        user=user if getattr(user, "is_authenticated", False) else None,
        organization=organization,
        action=str(action)[:255],
        target_type=str(target_type or "")[:100],
        target_id=str(target_id)[:100] if target_id is not None else None,
        metadata=_sanitize_metadata(metadata),
        ip_address=_client_ip(request),
    )
