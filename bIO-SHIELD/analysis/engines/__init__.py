import hashlib
import re
from types import SimpleNamespace

_DEFAULTS = {
    "ENABLE_PRESIDIO": False,
    "ENABLE_SPACY_MODEL": True,
    "RISK_MODEL_PATH": None,
}

_CONTEXT_PATTERNS = (
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(
        r"\b(?:MRN|Medical Record(?: Number)?|Policy|Insurance ID)\s*"
        r"[:#-]?\s*[A-Z0-9][A-Z0-9-]{3,24}\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:DOB|Date of Birth)\s*[:#-]?\s*\d{4}-\d{2}-\d{2}\b", re.IGNORECASE),
    re.compile(r"\bICD-?10\s*[:#-]?\s*[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b", re.IGNORECASE),
)


def safe_settings():
    values = dict(_DEFAULTS)
    try:
        from django.conf import settings as django_settings

        if getattr(django_settings, "configured", False):
            for key in list(values):
                values[key] = getattr(django_settings, key, values[key])
            for name in dir(django_settings):
                if name.isupper() and name not in values:
                    values[name] = getattr(django_settings, name, None)
    except Exception:
        pass
    return SimpleNamespace(**values)


def mask_value(value, keep=2):
    if value is None:
        return "[REDACTED]"
    text = str(value)
    if not text:
        return "[REDACTED]"
    try:
        amount = max(0, int(keep))
    except (TypeError, ValueError):
        amount = 2
    if amount == 0 or len(text) <= amount * 2 + 1:
        return "*" * len(text)
    hidden = "*" * min(12, len(text) - amount * 2)
    return f"{text[:amount]}{hidden}{text[-amount:]}"


def safe_preview(text, start, end, radius=40):
    if text is None:
        return ""
    value = str(text)
    try:
        start = int(start)
        end = int(end)
        radius = max(0, int(radius))
    except (TypeError, ValueError):
        return ""
    if start < 0 or end < start or start > len(value) or end > len(value):
        return ""
    if start == end:
        start = 0
        end = len(value)
        left = 0
        right = len(value)
        target = value
    else:
        left = max(0, start - radius)
        right = min(len(value), end + radius)
        target = value[start:end]
    preview = value[left:start] + mask_value(target) + value[end:right]
    if left > 0:
        preview = "..." + preview
    if right < len(value):
        preview = preview + "..."
    for pattern in _CONTEXT_PATTERNS:
        preview = pattern.sub(lambda match: mask_value(match.group(0), keep=1), preview)
    return preview


def sha256_text(text):
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()
