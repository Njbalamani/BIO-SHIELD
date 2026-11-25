from collections.abc import Mapping

_SEVERITY_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
_SUPPORTED_FORMATS = {"txt", "docx", "pdf"}


def _get(record, key, default=None):
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def _as_findings(findings):
    if findings is None:
        return []
    if isinstance(findings, Mapping):
        return [findings]
    try:
        return list(findings)
    except TypeError:
        return []


def _normalize_rules(rules):
    normalized = {}
    if rules is None:
        return normalized
    if not isinstance(rules, Mapping):
        return normalized
    for key, value in rules.items():
        if isinstance(value, Mapping):
            for nested_key, nested_value in value.items():
                normalized[str(nested_key).upper()] = str(nested_value)
        else:
            normalized[str(key).upper()] = str(value)
    return normalized


def _rank(severity):
    return _SEVERITY_RANK.get(str(severity).upper(), 0)


def _confidence(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:
        return 0.0
    return max(0.0, min(1.0, number))


def _replacement(finding, rules):
    finding_type = str(_get(finding, "finding_type", "") or "").upper()
    category = str(_get(finding, "category", "") or "").upper()
    for key in (finding_type, category):
        if key and key in rules:
            return rules[key]
    if category:
        return f"[REDACTED_{category}]"
    return "[REDACTED_CATEGORY]"


def apply_redaction(text, findings, rules=None, output_format="txt"):
    warnings = []
    text = str(text) if text is not None else ""
    requested_format = str(output_format or "txt").strip().lower().lstrip(".")
    normalized_format = requested_format if requested_format in _SUPPORTED_FORMATS else "txt"
    if normalized_format != requested_format:
        warnings.append(f"Unsupported output format {requested_format!r}; plain text output was used.")
    normalized_rules = _normalize_rules(rules)
    if rules is not None and not isinstance(rules, Mapping):
        warnings.append("Rules must be a mapping; default replacements were used.")
    records = _as_findings(findings)
    candidates = []
    invalid_spans = 0
    for record in records:
        try:
            start = int(_get(record, "start_offset"))
            end = int(_get(record, "end_offset"))
        except (TypeError, ValueError):
            invalid_spans += 1
            continue
        if start < 0 or end <= start or end > len(text):
            invalid_spans += 1
            continue
        category = str(_get(record, "category", "") or "UNKNOWN").upper()
        finding_type = str(_get(record, "finding_type", "") or "UNKNOWN").upper()
        candidates.append(
            {
                "start": start,
                "end": end,
                "category": category,
                "finding_type": finding_type,
                "severity": str(_get(record, "severity", "LOW") or "LOW").upper(),
                "confidence": _confidence(_get(record, "confidence", 0.0)),
                "replacement": _replacement(record, normalized_rules),
            }
        )
    candidates.sort(
        key=lambda item: (
            item["start"],
            -item["end"],
            -_rank(item["severity"]),
            -item["confidence"],
            item["finding_type"],
        )
    )
    selected = []
    overlap_count = 0
    last_end = -1
    for candidate in candidates:
        if candidate["start"] < last_end:
            overlap_count += 1
            continue
        selected.append(candidate)
        last_end = candidate["end"]
    if overlap_count:
        warnings.append("Overlapping finding spans were skipped to avoid duplicate edits.")
    if invalid_spans:
        warnings.append("Findings with invalid offsets were skipped.")
    sanitized_text = text
    replacements_by_category = {}
    replacements_by_finding_type = {}
    for candidate in sorted(selected, key=lambda item: item["start"], reverse=True):
        sanitized_text = (
            sanitized_text[: candidate["start"]] + candidate["replacement"] + sanitized_text[candidate["end"] :]
        )
        replacements_by_category[candidate["category"]] = replacements_by_category.get(candidate["category"], 0) + 1
        replacements_by_finding_type[candidate["finding_type"]] = (
            replacements_by_finding_type.get(candidate["finding_type"], 0) + 1
        )
    summary = {
        "output_format": normalized_format,
        "requested_output_format": requested_format,
        "original_length": len(text),
        "sanitized_length": len(sanitized_text),
        "redactions_applied": len(selected),
        "skipped_overlapping_spans": overlap_count,
        "invalid_spans": invalid_spans,
        "replacements_by_category": replacements_by_category,
        "replacements_by_finding_type": replacements_by_finding_type,
        "rendered": False,
        "rendering_note": "File rendering is handled elsewhere.",
    }
    return sanitized_text, summary, warnings
