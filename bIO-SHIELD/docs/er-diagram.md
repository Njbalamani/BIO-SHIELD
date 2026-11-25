# Entity relationship diagram

The model below describes the synthetic workspace schema. All identifiers are internal database keys; displayed identifiers such as `SYN-MRN-000001` come only from fabricated sample files.

```mermaid
erDiagram
    Organization ||--o{ User : has_members
    Organization ||--o{ Document : scopes
    User ||--o{ Document : uploads
    User ||--o{ Finding : reviews
    User ||--o{ AccessEvent : generates
    Document ||--o{ Finding : contains
    Document ||--o{ Assessment : evaluated_by
    Document ||--o{ AccessEvent : referenced_by
    Finding ||--o{ AnonymizationOperation : masked_by
    Assessment ||--o{ ComplianceCheck : mapped_to
    Assessment ||--o{ Report : produces

    Organization {
        bigint id PK
        string name
        string slug UK
        text description
        datetime created_at
    }
    User {
        bigint id PK
        string username UK
        string email UK
        string role
        bigint organization_id FK
        datetime last_login
    }
    Document {
        bigint id PK
        bigint organization_id FK
        bigint uploaded_by_id FK
        string title
        string document_type
        string status
        text extracted_text
        text masked_content
        datetime created_at
    }
    Finding {
        bigint id PK
        bigint document_id FK
        bigint reviewed_by_id FK
        string entity_type
        float confidence
        integer start
        integer end
        string detector
        string review_status
        datetime reviewed_at
    }
    AnonymizationOperation {
        bigint id PK
        bigint finding_id FK
        string method
        string masked_value
        datetime applied_at
    }
    Assessment {
        bigint id PK
        bigint document_id FK
        string risk_level
        integer score
        string framework
        datetime created_at
    }
    ComplianceCheck {
        bigint id PK
        bigint assessment_id FK
        string control_id
        string framework
        string evidence_status
        datetime updated_at
    }
    Report {
        bigint id PK
        bigint assessment_id FK
        string title
        string format
        string status
        datetime generated_at
    }
    AccessEvent {
        bigint id PK
        bigint actor_id FK
        bigint document_id FK
        string event_type
        string ip_address
        string outcome
        string risk_signal
        datetime timestamp
    }
```

## Table notes

| Table | Notes |
| --- | --- |
| Organization | Provides workspace scoping; slug is unique and human readable. |
| User | Extends the Django user model with a role and organization reference. |
| Document | Stores extraction and masked text separately; status drives the review queue. |
| Finding | `start` and `end` are character offsets into extracted text; confidence is normalized from 0 to 1. |
| AnonymizationOperation | Records the masking method and replacement token for each accepted finding. |
| Assessment | Aggregates findings into a risk band and numeric score. |
| ComplianceCheck | Maps evidence to internal control identifiers; completion is not certification. |
| Report | Stores metadata for generated sample reports rather than treating reports as authoritative records. |
| AccessEvent | Append-only audit entries with request correlation and documented synthetic IP ranges in samples. |

## Indexing guidance

- Index `Document(organization_id, created_at)` for register queries.
- Index `Finding(document_id, review_status)` for queue queries.
- Index `AccessEvent(timestamp)` and `AccessEvent(actor_id, timestamp)` for audit filtering.
- Enforce uniqueness on `Organization.slug`, `User.username` and `User.email`.

## Retention

`RETENTION_DAYS` defaults to 365. A scheduled task may prune synthetic documents and audit rows after the window, subject to locally documented legal and operational requirements. Samples are intentionally disposable.
