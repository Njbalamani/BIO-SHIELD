import re

from . import mask_value, safe_preview, safe_settings, sha256_text

_REGEX_RULES = (
    {
        "label": "email",
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "group": 0,
        "category": "CONTACT",
        "finding_type": "EMAIL",
        "severity": "HIGH",
        "confidence": 0.98,
    },
    {
        "label": "phone",
        "pattern": re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "group": 0,
        "category": "CONTACT",
        "finding_type": "PHONE",
        "severity": "HIGH",
        "confidence": 0.92,
    },
    {
        "label": "ssn",
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "group": 0,
        "category": "PHI",
        "finding_type": "SSN",
        "severity": "CRITICAL",
        "confidence": 0.99,
    },
    {
        "label": "mrn",
        "pattern": re.compile(
            r"\b(?:MRN|Medical Record(?: Number)?|Record(?: No\.?| Number)?)\b\s*"
            r"[:#-]?\s*([A-Z0-9][A-Z0-9-]{3,19})\b",
            re.IGNORECASE,
        ),
        "group": 1,
        "category": "PHI",
        "finding_type": "MRN",
        "severity": "HIGH",
        "confidence": 0.93,
    },
    {
        "label": "insurance_id",
        "pattern": re.compile(
            r"\b(?:insurance\s*(?:id|no\.?|number)|policy\s*(?:id|no\.?|number)?|member\s*(?:id|number))\b\s*"
            r"[:#-]?\s*([A-Z0-9][A-Z0-9-]{3,24})\b",
            re.IGNORECASE,
        ),
        "group": 1,
        "category": "PHI",
        "finding_type": "INSURANCE_ID",
        "severity": "HIGH",
        "confidence": 0.9,
    },
    {
        "label": "dob",
        "pattern": re.compile(
            r"\b(?:DOB|Date of Birth|Birth ?date|Born)\b\s*[:#-]?\s*"
            r"(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4})\b",
            re.IGNORECASE,
        ),
        "group": 1,
        "category": "PHI",
        "finding_type": "DATE_OF_BIRTH",
        "severity": "HIGH",
        "confidence": 0.95,
    },
    {
        "label": "icd10",
        "pattern": re.compile(r"\bICD-?10\b\s*[:#-]?\s*([A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?)\b", re.IGNORECASE),
        "group": 1,
        "category": "CLINICAL",
        "finding_type": "ICD10_CODE",
        "severity": "HIGH",
        "confidence": 0.96,
    },
    {
        "label": "name",
        "pattern": re.compile(
            r"\b(?:Patient\s+Name|Full\s+Name|Name)\b\s*[:#-]?\s*"
            r"([A-Z][A-Za-z'’-]+(?:\s+[A-Z][A-Za-z'’-]+){0,3})\b"
        ),
        "group": 1,
        "category": "PII",
        "finding_type": "NAME",
        "severity": "MODERATE",
        "confidence": 0.9,
    },
    {
        "label": "address",
        "pattern": re.compile(
            r"\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'’-]+\s+){0,4}"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Terrace|Ter|Parkway|Pkwy)\b"
            r"\.?(?:\s*,?\s*[A-Z][A-Za-z .'-]+,?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)?"
        ),
        "group": 0,
        "category": "PII",
        "finding_type": "ADDRESS",
        "severity": "HIGH",
        "confidence": 0.85,
    },
    {
        "label": "medication",
        "pattern": re.compile(
            r"\b(?:Metformin|Lisinopril|Atorvastatin|Amlodipine|Omeprazole|Aspirin|"
            r"Ibuprofen|Acetaminophen|Insulin|Warfarin|Levothyroxine|Albuterol|"
            r"Amoxicillin|Simvastatin|Clopidogrel|Losartan|Hydrochlorothiazide|"
            r"Gabapentin|Sertraline|Tylenol|Advil)\b",
            re.IGNORECASE,
        ),
        "group": 0,
        "category": "CLINICAL",
        "finding_type": "MEDICATION",
        "severity": "MODERATE",
        "confidence": 0.87,
    },
    {
        "label": "diagnosis",
        "pattern": re.compile(
            r"\b(?:Chronic kidney disease|Coronary artery disease|Atrial fibrillation|Hyperlipidemia|"
            r"Hypertension|Depression|Migraine|Arthritis|Diabetes|Asthma|COPD|Cancer|Anxiety|"
            r"Infection|COVID-19|Epilepsy|Stroke|Heart failure)\b",
            re.IGNORECASE,
        ),
        "group": 0,
        "category": "CLINICAL",
        "finding_type": "DIAGNOSIS",
        "severity": "MODERATE",
        "confidence": 0.82,
    },
)

_SEVERITY_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}

_PRESIDIO_MAP = {
    "EMAIL_ADDRESS": ("CONTACT", "EMAIL", "HIGH", 0.95),
    "PHONE_NUMBER": ("CONTACT", "PHONE", "HIGH", 0.93),
    "US_SSN": ("PHI", "SSN", "CRITICAL", 0.98),
    "US_PASSPORT": ("PHI", "GOVERNMENT_ID", "CRITICAL", 0.9),
    "US_DRIVER_LICENSE": ("PHI", "GOVERNMENT_ID", "CRITICAL", 0.9),
    "MEDICAL_LICENSE": ("PHI", "INSURANCE_ID", "HIGH", 0.88),
    "PERSON": ("PII", "NAME", "MODERATE", 0.8),
    "LOCATION": ("PII", "ADDRESS", "HIGH", 0.75),
    "IP_ADDRESS": ("CONTACT", "CONTACT_DETAIL", "MODERATE", 0.8),
    "CREDIT_CARD": ("FINANCIAL", "FINANCIAL_IDENTIFIER", "CRITICAL", 0.95),
    "US_BANK_NUMBER": ("FINANCIAL", "FINANCIAL_IDENTIFIER", "CRITICAL", 0.93),
}

_SPACY_MAP = {
    "EMAIL": ("CONTACT", "EMAIL", "HIGH", 0.9),
    "EMAIL_ADDRESS": ("CONTACT", "EMAIL", "HIGH", 0.9),
    "PHONE": ("CONTACT", "PHONE", "HIGH", 0.88),
    "PHONE_NUMBER": ("CONTACT", "PHONE", "HIGH", 0.88),
    "SSN": ("PHI", "SSN", "CRITICAL", 0.95),
    "US_SSN": ("PHI", "SSN", "CRITICAL", 0.95),
    "MRN": ("PHI", "MRN", "HIGH", 0.93),
    "MEDICAL_RECORD_NUMBER": ("PHI", "MRN", "HIGH", 0.93),
    "INSURANCE_ID": ("PHI", "INSURANCE_ID", "HIGH", 0.9),
    "DATE_OF_BIRTH": ("PHI", "DATE_OF_BIRTH", "HIGH", 0.92),
    "ICD10": ("CLINICAL", "ICD10_CODE", "HIGH", 0.94),
    "ICD10_CODE": ("CLINICAL", "ICD10_CODE", "HIGH", 0.94),
    "MEDICATION": ("CLINICAL", "MEDICATION", "MODERATE", 0.85),
    "DIAGNOSIS": ("CLINICAL", "DIAGNOSIS", "MODERATE", 0.82),
    "PERSON": ("PII", "NAME", "MODERATE", 0.8),
    "GPE": ("PII", "ADDRESS", "HIGH", 0.72),
    "LOC": ("PII", "ADDRESS", "HIGH", 0.72),
    "ADDRESS": ("PII", "ADDRESS", "HIGH", 0.78),
}

_BIRTH_TERMS = ("dob", "birth", "born", "date of birth")


class _NullDoc:
    def __init__(self, text):
        self.text = text
        self.ents = []


class _NullRuler:
    def add_patterns(self, patterns):
        return None


class _NullNLP:
    def __init__(self, warnings=None):
        self.pipe_names = []
        self.bioshield_warnings = list(warnings or [])

    def __call__(self, text):
        return _NullDoc(text)

    def add_pipe(self, *args, **kwargs):
        return _NullRuler()


def _entity_ruler_patterns():
    return (
        {
            "label": "EMAIL_ADDRESS",
            "pattern": r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "type": "regex",
        },
        {
            "label": "PHONE_NUMBER",
            "pattern": r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "type": "regex",
        },
        {
            "label": "SSN",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "type": "regex",
        },
        {
            "label": "MRN",
            "pattern": r"(?i)\b(?:MRN|Medical Record(?: Number)?)\b\s*"
            r"[:#-]?\s*[A-Z0-9][A-Z0-9-]{3,19}\b",
            "type": "regex",
        },
        {
            "label": "DATE_OF_BIRTH",
            "pattern": r"(?i)\b(?:DOB|Date of Birth)\b\s*[:#-]?\s*\d{4}-\d{2}-\d{2}\b",
            "type": "regex",
        },
        {
            "label": "ICD10_CODE",
            "pattern": r"(?i)\bICD-?10\b\s*[:#-]?\s*[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b",
            "type": "regex",
        },
        {
            "label": "MEDICATION",
            "pattern": r"(?i)\b(?:Metformin|Lisinopril|Atorvastatin|Amlodipine|Omeprazole|Aspirin|"
            r"Insulin|Warfarin|Levothyroxine|Albuterol|Amoxicillin|Simvastatin|"
            r"Clopidogrel|Losartan|Gabapentin|Sertraline)\b",
            "type": "regex",
        },
        {
            "label": "DIAGNOSIS",
            "pattern": r"(?i)\b(?:Diabetes|Hypertension|Asthma|COPD|Cancer|Depression|Anxiety|"
            r"Hyperlipidemia|Migraine|Arthritis|Infection|COVID-19|Epilepsy|Stroke)\b",
            "type": "regex",
        },
    )


def load_nlp():
    settings = safe_settings()
    warnings = []
    try:
        import spacy
    except Exception:
        return _NullNLP(["spaCy is unavailable; regex rules were used."])
    nlp = None
    if bool(getattr(settings, "ENABLE_SPACY_MODEL", False)):
        try:
            nlp = spacy.load("en_core_web_sm")
        except Exception:
            warnings.append("spaCy model en_core_web_sm is unavailable; blank English NER with entity rules was used.")
    if nlp is None:
        try:
            nlp = spacy.blank("en")
        except Exception:
            return _NullNLP(warnings + ["spaCy blank English pipeline is unavailable; regex rules were used."])
    try:
        if "phi_entity_ruler" not in nlp.pipe_names:
            if "ner" in nlp.pipe_names:
                ruler = nlp.add_pipe("entity_ruler", name="phi_entity_ruler", before="ner")
            else:
                ruler = nlp.add_pipe("entity_ruler", name="phi_entity_ruler")
            if ruler is not None:
                ruler.add_patterns(_entity_ruler_patterns())
    except Exception:
        warnings.append("spaCy entity rules could not be configured; regex rules were used.")
    nlp.bioshield_warnings = warnings
    return nlp


def _as_text(text):
    if text is None:
        return ""
    return str(text)


def _trim_span(text, start, end):
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _clamp(value, low=0.0, high=1.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return low
    if number != number:
        return low
    return max(low, min(high, number))


def _severity_rank(severity):
    return _SEVERITY_RANK.get(str(severity).upper(), 0)


def _context_indicates_birth(text, start, end):
    window = text[max(0, start - 40) : min(len(text), end + 40)].lower()
    return any(term in window for term in _BIRTH_TERMS)


def _add_candidate(candidates, text, start, end, category, finding_type, severity, confidence, methodology, result):
    try:
        start = int(start)
        end = int(end)
    except (TypeError, ValueError):
        return
    start, end = _trim_span(text, start, end)
    if start < 0 or end > len(text) or start >= end:
        return
    raw_value = text[start:end]
    candidates.append(
        {
            "start_offset": start,
            "end_offset": end,
            "category": category,
            "finding_type": finding_type,
            "severity": severity,
            "confidence": _clamp(confidence),
            "methodologies": {methodology},
            "raw_value": raw_value,
            "raw_sources": [{"engine": methodology, "result": result}],
        }
    )


def _regex_candidates(text):
    candidates = []
    for rule in _REGEX_RULES:
        group = int(rule.get("group", 0))
        for match in rule["pattern"].finditer(text):
            if group > len(match.groups()):
                continue
            start, end = match.span(group)
            if start < 0 or end < 0:
                continue
            _add_candidate(
                candidates,
                text,
                start,
                end,
                rule["category"],
                rule["finding_type"],
                rule["severity"],
                rule["confidence"],
                "regex",
                {"label": rule["label"], "value": match.group(group)},
            )
    return candidates


def _presidio_nlp_engine():
    from presidio_analyzer.nlp_engine import NlpArtifacts, NlpEngine

    pipeline = load_nlp()

    class BioShieldNlpEngine(NlpEngine):
        def __init__(self, nlp):
            self.nlp = nlp

        def load(self):
            return None

        def is_loaded(self):
            return True

        def get_supported_languages(self):
            return ["en"]

        def get_supported_entities(self):
            return sorted(set(_SPACY_MAP) | set(_PRESIDIO_MAP) | {"DATE_TIME"})

        def is_stopword(self, word, language):
            vocab = getattr(self.nlp, "vocab", None)
            if vocab is None:
                return False
            return bool(getattr(vocab[word], "is_stop", False))

        def is_punct(self, word, language):
            vocab = getattr(self.nlp, "vocab", None)
            if vocab is None:
                return False
            return bool(getattr(vocab[word], "is_punct", False))

        def process_text(self, text, language):
            doc = self.nlp(text)
            tokens = list(doc) if hasattr(doc, "__iter__") else []
            lemmas = [str(getattr(token, "lemma_", getattr(token, "text", ""))) for token in tokens]
            indices = [int(getattr(token, "idx", 0)) for token in tokens]
            entities = list(getattr(doc, "ents", []))
            scores = [1.0 for _ in entities]
            return NlpArtifacts(
                entities=entities,
                tokens=tokens,
                tokens_indices=indices,
                lemmas=lemmas,
                nlp_engine=self,
                language=language,
                scores=scores,
            )

        def process_batch(self, texts, language, batch_size=1, n_process=1, **kwargs):
            for text in texts:
                value = str(text)
                yield value, self.process_text(value, language)

    return BioShieldNlpEngine(pipeline)


def _presidio_candidates(text, warnings):
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception:
        warnings.append("Presidio is unavailable; Presidio-based detection was skipped.")
        return []
    try:
        analyzer = AnalyzerEngine(nlp_engine=_presidio_nlp_engine(), supported_languages=["en"])
        results = analyzer.analyze(text=text, language="en")
    except Exception as exc:
        warnings.append(f"Presidio analysis failed ({type(exc).__name__}); regex rules were used.")
        return []
    candidates = []
    for result in results or []:
        try:
            start = int(result.start)
            end = int(result.end)
        except (TypeError, ValueError, AttributeError):
            continue
        entity_type = str(getattr(result, "entity_type", "")).upper()
        mapping = _PRESIDIO_MAP.get(entity_type)
        if entity_type == "DATE_TIME" and _context_indicates_birth(text, start, end):
            mapping = ("PHI", "DATE_OF_BIRTH", "HIGH", 0.9)
        if mapping is None:
            continue
        category, finding_type, severity, default_confidence = mapping
        score = getattr(result, "score", default_confidence)
        _add_candidate(
            candidates,
            text,
            start,
            end,
            category,
            finding_type,
            severity,
            score if score is not None else default_confidence,
            "presidio",
            {"entity_type": entity_type, "score": score},
        )
    return candidates


def _spacy_candidates(text, warnings):
    nlp = load_nlp()
    for warning in getattr(nlp, "bioshield_warnings", []):
        if warning not in warnings:
            warnings.append(warning)
    try:
        doc = nlp(text)
    except Exception as exc:
        warnings.append(f"spaCy analysis failed ({type(exc).__name__}); regex rules were used.")
        return []
    candidates = []
    for entity in getattr(doc, "ents", []):
        try:
            start = int(entity.start_char)
            end = int(entity.end_char)
        except (TypeError, ValueError, AttributeError):
            continue
        label = str(getattr(entity, "label_", "")).upper()
        mapping = _SPACY_MAP.get(label)
        if label == "DATE" and _context_indicates_birth(text, start, end):
            mapping = ("PHI", "DATE_OF_BIRTH", "HIGH", 0.8)
        if mapping is None:
            continue
        category, finding_type, severity, confidence = mapping
        _add_candidate(
            candidates,
            text,
            start,
            end,
            category,
            finding_type,
            severity,
            confidence,
            "spacy",
            {"label": label},
        )
    return candidates


def _merge_candidates(candidates):
    merged = {}
    for candidate in candidates:
        key = (candidate["start_offset"], candidate["end_offset"], candidate["finding_type"])
        current = merged.get(key)
        if current is None:
            current = dict(candidate)
            current["methodologies"] = set(candidate["methodologies"])
            current["raw_sources"] = list(candidate["raw_sources"])
            merged[key] = current
            continue
        current["methodologies"].update(candidate["methodologies"])
        current["confidence"] = max(current["confidence"], candidate["confidence"])
        if _severity_rank(candidate["severity"]) > _severity_rank(current["severity"]):
            current["severity"] = candidate["severity"]
            current["category"] = candidate["category"]
        current["raw_sources"].extend(candidate["raw_sources"])
    return [merged[key] for key in sorted(merged, key=lambda item: (item[0], item[1], item[2]))]


def _finalize_findings(candidates, text, source_name):
    findings = []
    for candidate in candidates:
        start = candidate["start_offset"]
        end = candidate["end_offset"]
        raw_value = candidate["raw_value"]
        finding_type = candidate["finding_type"]
        methodology = ", ".join(sorted(candidate["methodologies"]))
        confidence = round(_clamp(candidate["confidence"]), 3)
        findings.append(
            {
                "category": candidate["category"],
                "finding_type": finding_type,
                "severity": candidate["severity"],
                "confidence": confidence,
                "methodology": methodology,
                "start_offset": start,
                "end_offset": end,
                "line_number": text.count("\n", 0, start) + 1,
                "value_masked": mask_value(raw_value),
                "fingerprint": sha256_text(f"{finding_type}|{raw_value.casefold()}"),
                "context_masked": safe_preview(text, start, end),
                "raw_value": raw_value,
                "raw": {
                    "value": raw_value,
                    "source": source_name,
                    "sources": candidate["raw_sources"],
                },
            }
        )
    return findings


def detect_findings(text, source_name="document", use_presidio=None, use_spacy=None):
    text = _as_text(text)
    warnings = []
    settings = safe_settings()
    presidio_setting = bool(getattr(settings, "ENABLE_PRESIDIO", False))
    spacy_setting = bool(getattr(settings, "ENABLE_SPACY_MODEL", True))
    presidio_requested = presidio_setting if use_presidio is None else bool(use_presidio) and presidio_setting
    spacy_requested = spacy_setting if use_spacy is None else bool(use_spacy)
    if use_presidio is True and not presidio_setting:
        warnings.append("Presidio is disabled by settings; Presidio-based detection was skipped.")
    regex_candidates = _regex_candidates(text)
    presidio_candidates = _presidio_candidates(text, warnings) if presidio_requested else []
    spacy_candidates = _spacy_candidates(text, warnings) if spacy_requested else []
    candidates = _merge_candidates(regex_candidates + presidio_candidates + spacy_candidates)
    findings = _finalize_findings(candidates, text, source_name)
    counts_by_category = {}
    counts_by_severity = {}
    counts_by_finding_type = {}
    methodologies = {"regex"}
    if presidio_candidates:
        methodologies.add("presidio")
    if spacy_candidates:
        methodologies.add("spacy")
    for finding in findings:
        category = str(finding["category"])
        severity = str(finding["severity"])
        finding_type = str(finding["finding_type"])
        counts_by_category[category] = counts_by_category.get(category, 0) + 1
        counts_by_severity[severity] = counts_by_severity.get(severity, 0) + 1
        counts_by_finding_type[finding_type] = counts_by_finding_type.get(finding_type, 0) + 1
        for method in str(finding["methodology"]).split(","):
            method = method.strip().lower()
            if method:
                methodologies.add(method)
    unique_warnings = []
    for warning in warnings:
        if warning not in unique_warnings:
            unique_warnings.append(warning)
    methodology_list = sorted(methodologies)
    summary = {
        "source_name": source_name,
        "total_findings": len(findings),
        "counts_by_category": counts_by_category,
        "counts_by_severity": counts_by_severity,
        "counts_by_finding_type": counts_by_finding_type,
        "category_counts": counts_by_category,
        "severity_counts": counts_by_severity,
        "methodologies": methodology_list,
        "methodology": methodology_list,
        "warnings": unique_warnings,
        "engines": {"regex": True, "presidio": presidio_requested, "spacy": spacy_requested},
    }
    return findings, summary
