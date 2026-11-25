import os
from collections.abc import Mapping

from . import safe_settings

_SEVERITY_WEIGHTS = {"LOW": 2.0, "MODERATE": 5.0, "HIGH": 9.0, "CRITICAL": 14.0}
_PHI_TYPES = {
    "SSN",
    "MRN",
    "INSURANCE_ID",
    "DATE_OF_BIRTH",
    "ICD10_CODE",
    "MEDICATION",
    "DIAGNOSIS",
    "GOVERNMENT_ID",
}
_EXPOSURE_WEIGHTS = {
    "external": 0.9,
    "public": 0.9,
    "third": 0.8,
    "email": 0.6,
    "attachment": 0.6,
    "bulk": 0.7,
    "export": 0.7,
    "unencrypted": 0.8,
    "share": 0.6,
    "download": 0.5,
    "vendor": 0.7,
    "cloud": 0.5,
}
_TRUE_TERMS = {"true", "yes", "high", "enabled", "shared", "external", "present"}
_FALSE_TERMS = {"false", "no", "none", "0", "low", "disabled", "absent"}


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


def _as_events(events):
    if events is None:
        return []
    if isinstance(events, Mapping):
        return [events]
    try:
        return list(events)
    except TypeError:
        return []


def _clamp(value, low=0.0, high=1.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return low
    if number != number:
        return low
    return max(low, min(high, number))


def _exposure_factor(exposure_factors):
    if exposure_factors is None:
        return 0.0, {}
    if isinstance(exposure_factors, Mapping):
        source = dict(exposure_factors)
    elif isinstance(exposure_factors, (int, float)) and not isinstance(exposure_factors, bool):
        value = round(_clamp(exposure_factors), 3)
        return value, {"provided_factor": value}
    else:
        return 0.0, {}
    details = {}
    for key, value in source.items():
        label = str(key).lower()
        weight = 0.4
        for term, specific_weight in _EXPOSURE_WEIGHTS.items():
            if term in label:
                weight = specific_weight
                break
        if isinstance(value, bool):
            amount = weight if value else 0.0
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            amount = _clamp(value)
        elif isinstance(value, str):
            text = value.strip().lower()
            if text in _TRUE_TERMS:
                amount = weight
            elif text in _FALSE_TERMS:
                amount = 0.0
            else:
                amount = weight * 0.5
        elif value is None:
            amount = 0.0
        else:
            amount = weight
        details[str(key)] = round(amount, 3)
    return round(min(1.0, sum(details.values())), 3), details


def _model_score(features, model_path=None):
    configured_path = model_path or getattr(safe_settings(), "RISK_MODEL_PATH", None)
    if not configured_path:
        return None, "Risk model path is not configured; deterministic heuristic used."
    path = str(configured_path)
    if not os.path.exists(path):
        return None, "Configured risk model file was not found; deterministic heuristic used."
    model = None
    try:
        from joblib import load

        model = load(path)
    except Exception:
        try:
            import pickle

            with open(path, "rb") as handle:
                model = pickle.load(handle)
        except Exception as exc:
            return None, f"Risk model could not be loaded ({type(exc).__name__}); deterministic heuristic used."
    try:
        matrix = [features]
        if hasattr(model, "predict_proba"):
            probabilities = list(model.predict_proba(matrix)[0])
            classes = list(getattr(model, "classes_", []))
            if 1 in classes:
                index = classes.index(1)
            elif True in classes:
                index = classes.index(True)
            else:
                index = max(range(len(probabilities)), key=lambda position: probabilities[position])
            score = float(probabilities[index]) * 100.0
        else:
            score = float(model.predict(matrix)[0])
            if score <= 1.0:
                score *= 100.0
        if score != score or score < 0.0 or score > 100.0:
            raise ValueError("model output outside supported range")
        return round(score, 2), "Risk model refined the deterministic score."
    except Exception as exc:
        return None, f"Risk model prediction failed ({type(exc).__name__}); deterministic heuristic used."


def calculate_privacy_risk(findings, access_events=None, exposure_factors=None, model_path=None):
    records = _as_findings(findings)
    categories = {}
    severities = []
    confidence_values = []
    phi_count = 0
    for record in records:
        category = str(_get(record, "category", "UNKNOWN") or "UNKNOWN").upper()
        severity = str(_get(record, "severity", "LOW") or "LOW").upper()
        finding_type = str(_get(record, "finding_type", "") or "").upper()
        categories[category] = categories.get(category, 0) + 1
        severities.append(severity)
        confidence_values.append(_clamp(_get(record, "confidence", 0.0)))
        if category in {"PHI", "CLINICAL"} or finding_type in _PHI_TYPES:
            phi_count += 1
    high_severity_count = sum(1 for severity in severities if severity in {"HIGH", "CRITICAL"})
    confidence_average = round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0
    try:
        from .access import detect_anomalies

        _, alerts = detect_anomalies(_as_events(access_events))
    except Exception:
        alerts = []
    alert_count = len(alerts)
    alert_severities = [str(_get(alert, "severity", "LOW")).upper() for alert in alerts]
    exposure_factor, exposure_details = _exposure_factor(exposure_factors)
    severity_points = sum(_SEVERITY_WEIGHTS.get(severity, 0.0) for severity in severities)
    heuristic_score = (
        min(severity_points, 45.0)
        + min(len(categories) * 2.0, 10.0)
        + min(high_severity_count * 3.0, 15.0)
        + min(phi_count * 2.0, 15.0)
        + confidence_average * 5.0
        + min(alert_count * 4.0, 12.0)
        + exposure_factor * 15.0
    )
    heuristic_score = round(max(0.0, min(100.0, heuristic_score)), 2)
    features = [
        len(records),
        len(categories),
        high_severity_count,
        phi_count,
        confidence_average,
        alert_count,
        exposure_factor,
    ]
    model_score, model_detail = _model_score(features, model_path=model_path)
    if model_score is None:
        score = heuristic_score
    else:
        score = round(max(0.0, min(100.0, 0.7 * heuristic_score + 0.3 * model_score)), 2)
    if score >= 75.0:
        level = "CRITICAL"
    elif score >= 45.0:
        level = "HIGH"
    elif score >= 20.0:
        level = "MODERATE"
    else:
        level = "LOW"
    indicators = [
        {
            "name": "sensitivity_mix",
            "value": categories,
            "detail": f"{len(categories)} distinct sensitivity categories across {len(records)} findings.",
            "weight": min(len(categories) * 2.0, 10.0),
        },
        {
            "name": "high_severity_count",
            "value": high_severity_count,
            "detail": "Findings marked high or critical severity increase priority.",
            "weight": min(high_severity_count * 3.0, 15.0),
        },
        {
            "name": "phi_count",
            "value": phi_count,
            "detail": "Findings containing identifiers or clinical information increase privacy risk.",
            "weight": min(phi_count * 2.0, 15.0),
        },
        {
            "name": "access_anomalies",
            "value": alert_count,
            "detail": "Anomalies observed in supplied access events increase risk.",
            "weight": min(alert_count * 4.0, 12.0),
        },
        {
            "name": "exposure_factor",
            "value": exposure_factor,
            "detail": "Sharing, export, and encryption exposure factors increase risk.",
            "weight": exposure_factor * 15.0,
        },
        {
            "name": "confidence_average",
            "value": confidence_average,
            "detail": "Average detector confidence contributes to the calculated score.",
            "weight": confidence_average * 5.0,
        },
        {
            "name": "risk_model_refinement",
            "value": model_score,
            "detail": model_detail,
            "weight": 0.0 if model_score is None else 0.3,
        },
    ]
    recommendations = []
    if high_severity_count:
        recommendations.append("Prioritize remediation for high and critical findings before sharing the document.")
    if phi_count:
        recommendations.append("Remove or encrypt PHI-bearing fields and restrict access to authorized users.")
    if "CLINICAL" in categories:
        recommendations.append("Review clinical terms and codes for minimum necessary disclosure.")
    if alert_count:
        recommendations.append("Investigate flagged access events and revoke sessions that cannot be verified.")
    if "CRITICAL" in alert_severities:
        recommendations.append("Escalate high-severity access anomalies to the security owner for review.")
    if exposure_factor:
        recommendations.append(
            "Disable public links and external exports until supplied exposure factors are resolved."
        )
    if confidence_average and confidence_average < 0.7:
        recommendations.append("Manually validate lower-confidence findings before applying automated redaction.")
    if not records and not alert_count and not exposure_factor:
        recommendations.append("Retain current safeguards and re-run detection after any document changes.")
    recommendations.append("Record remediation decisions and the detection methodology used for this review.")
    return score, level, indicators, recommendations
