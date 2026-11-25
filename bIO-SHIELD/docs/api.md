# API

BioShield exposes a REST API under `/api/`, alongside server-rendered HTML views. The API is intended for internal tooling and demonstrations in a synthetic-only environment.

## Authentication and CSRF

- Session authentication is used by the browser UI.
- Token authentication is enabled for service clients.
- Every state-changing session request must include a CSRF token via the `X-CSRFToken` header. The base template exposes it in a `<meta name="csrf-token">` tag, and `static/js/main.js` provides `BioShield.csrfToken()` and `BioShield.apiFetch()`.
- Rate limits are configured with `API_THROTTLE_ANON` and `API_THROTTLE_USER`.

## Endpoints

| Endpoint | Methods | Description |
| --- | --- | --- |
| `/api/auth/register/` | POST | Create a synthetic workspace account |
| `/api/auth/login/` | POST | Authenticate and obtain a token |
| `/api/auth/logout/` | POST | End the current session |
| `/api/auth/me/` | GET | Inspect the current account |
| `/api/organizations/` | GET, POST | List or create synthetic organizations |
| `/api/documents/` | GET, POST | List documents or upload a synthetic file |
| `/api/documents/{id}/` | GET, PATCH, DELETE | Inspect, rename or remove a document |
| `/api/documents/{id}/download/` | GET | Download an original document |
| `/api/documents/{id}/analyze/` | POST | Queue local analysis |
| `/api/documents/{id}/anonymize/` | POST | Queue redaction into a downloadable file |
| `/api/documents/{id}/access/` | GET, POST | Read or record access events |
| `/api/document-versions/` | GET, POST | List or add document versions |
| `/api/findings/` | GET, POST | List candidate findings with confidence and status |
| `/api/findings/{id}/review/` | POST | Submit reviewer decision |
| `/api/assessments/` | GET, POST | List or create risk assessments |
| `/api/assessments/generate/` | POST | Build an assessment from stored findings |
| `/api/anonymization-jobs/` | GET, POST | List and create masking operations |
| `/api/anonymization-jobs/{id}/download/` | GET | Download redacted output |
| `/api/access-events/` | GET, POST | Query and record access events |
| `/api/access-events/monitor/` | POST | Queue access anomaly monitoring |
| `/api/alerts/` | GET, PATCH | Review generated access alerts |
| `/api/checklists/` | GET, POST | List internal checklist items |
| `/api/reports/` | GET, POST | List report records |
| `/api/reports/{id}/download/` | GET | Download a generated PDF report |
| `/api/reports/generate/` | POST | Build a PDF report from workspace evidence |
| `/api/audit-logs/` | GET | Inspect sanitized audit history |
| `/api/dashboard/metrics/` | GET | Organization-scoped metrics payload |
| `/api/ai/status/` | GET | Local AI engine status and disclaimers |
| `/health/live/` | GET | Liveness response |
| `/health/ready/` | GET | Readiness response with database check |

## Pagination

List endpoints use page-based pagination with `page` and `page_size` query parameters. Responses include `count`, `next`, `previous` and `results`.

## Example document list response

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": "17",
      "title": "Synthetic patient summary",
      "file_type": "PDF",
      "status": "COMPLETED",
      "is_synthetic": true,
      "organization_name": "Northwind Example Clinic",
      "created_at": "2026-11-25T09:14:00Z"
    }
  ]
}
```

## Example finding review request

```json
{
  "status": "REVIEWED"
}
```

## Example finding review response

```json
{
  "finding_id": "91",
  "finding_type": "EMAIL",
  "value": "synthetic.alpha@example.invalid",
  "masked": false,
  "authorized": true,
  "status": "REVIEWED"
}
```

Privileged reviewers can receive the decrypted synthetic value. Unprivileged users receive `"value": "[REDACTED]"`, `"masked": true`, and `"authorized": false`.

## Error format

```json
{
  "detail": "Uploaded file exceeds the configured maximum size."
}
```

Common status codes: `400` validation failure, `401` unauthenticated, `403` forbidden, `404` not found, `413` file too large, `429` throttled, `500` unexpected error.

## Dashboard metrics shape

The dashboard template embeds the same payload in `<script id="dashboard-data" type="application/json">`:

```json
{
  "findings_by_category": {"PII": 12, "PHI": 8, "CONTACT": 5, "MEDICAL": 3},
  "findings_by_severity": {"HIGH": 4, "MEDIUM": 11, "LOW": 13},
  "average_risk_score": 42.5,
  "documents_total": 3,
  "findings_total": 31,
  "assessments_total": 3,
  "alerts_open": 2,
  "access_events_total": 120,
  "anonymization_jobs_total": 3
}
```

`static/js/dashboard.js` accepts equivalent arrays of `{label, value}` objects and degrades gracefully if Chart.js, the metrics script or data is absent.

## Client usage

```javascript
BioShield.apiFetch('/api/findings/91/review/', {
  method: 'POST',
  body: JSON.stringify({ status: 'REVIEWED' })
}).then(function (response) {
  if (!response.ok) throw new Error('Review failed');
  return response.json();
}).then(function (data) {
  BioShield.toast('Review recorded: ' + data.status);
});
```
