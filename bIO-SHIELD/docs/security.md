# Security

BioShield is a synthetic-data demonstration platform. The controls below describe intended safeguards; they do not make the project a certified clinical system.

## Threat model

| Asset | Threat | Mitigation |
| --- | --- | --- |
| Synthetic documents | Accidental upload of real patient data | Prominent banners, sample warnings and `SYNTHETIC_DATA_ONLY` flag |
| Findings and masked excerpts | Cross-site scripting via extracted text | Autoescaped templates and DOM text-only JavaScript |
| Session credentials | CSRF and cookie theft | CSRF tokens, secure cookies, SameSite policy and HTTPS |
| API | Enumeration and abuse | Authentication, permissions and rate limiting |
| Database | Credential compromise | Strong secrets, network isolation and field encryption support |
| Audit trail | Repudiation of reviewer actions | Append-only access events with request identifiers |
| Upload pipeline | Malicious file content | Size limits, type allow-list, isolated parsing and scan timeouts |

## HTTP hardening

`config/middleware.py` sets:

- `X-Request-ID` for correlation.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy` from `SECURE_REFERRER_POLICY`.
- `Permissions-Policy` from `SECURE_PERMISSIONS_POLICY`.
- `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`.
- `Content-Security-Policy` from `CONTENT_SECURITY_POLICY`.

Use HTTPS, HSTS, secure session and CSRF cookies, and explicit `ALLOWED_HOSTS` in production. The base template loads Three.js, GSAP and Chart.js from approved CDNs; include those origins in the CSP or self-host the assets and remove them from the policy.

## CSRF

The base template emits `<meta name="csrf-token" content="{{ csrf_token }}">`. `BioShield.csrfToken()` reads that value with a cookie fallback, and `BioShield.apiFetch()` adds `X-CSRFToken` to unsafe requests. Django templates render `{% csrf_token %}` inside all POST forms.

## Untrusted content handling

- Django autoescaping protects template variables.
- `static/js/dashboard.js` builds tables with `createElement` and `textContent`.
- `static/js/highlight.js` slices text by validated offsets and creates masked spans with `textContent`; it never assigns untrusted strings to `innerHTML`.
- `metrics_json` is marked safe only because views must serialize it with a JSON encoder; views are responsible for producing valid JSON.
- Uploaded files are parsed in Celery tasks with `SCAN_TIMEOUT_SECONDS` limits.

## Access control

- Accounts carry roles for analyst, reviewer and administrator workflows.
- Views and API endpoints enforce organization scoping and role checks.
- Sign-in, review, export and access events are written to `audit`.
- Require human review before any finding is considered final.

## Data protection

- `FIELD_ENCRYPTION_KEY` supplies a Fernet key for fields marked sensitive.
- Keep the key in a secret manager, never in source control.
- PostgreSQL and Redis are reachable only inside the compose network.
- `RETENTION_DAYS` controls scheduled pruning of synthetic documents and events.
- No production patient data should ever be present in this environment.

## File uploads

- `MAX_UPLOAD_SIZE_MB` defaults to 10.
- Accept only PDF, DOCX, TXT and CSV samples in the UI.
- Run extraction in workers, not in the web request path.
- Treat extracted text as untrusted and render it through the safe highlighting path.

## Dependencies

Pin or hash dependencies in regulated environments. Keep Django, DRF, Celery, Presidio, spaCy and report parsing libraries patched. The spaCy English model is installed from its published wheel URL compatible with spaCy 3.8.

## Incident response

1. Preserve request identifiers and audit exports.
2. Remove the affected synthetic artifact from service.
3. Rotate exposed credentials or encryption keys when applicable.
4. Review upload provenance and analyzer logs.
5. Document findings and corrective actions.

## Limitations

Automated detection produces candidates, not guarantees. False positives and false negatives are expected. Compliance checklist completion is not certification. See `docs/compliance-disclaimer.md`.
