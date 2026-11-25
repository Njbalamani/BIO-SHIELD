# Compliance disclaimer

BioShield includes compliance checklist views, framework mappings and sample reports. These features are **decision support only**.

## Explicit statement

Automated compliance checklists in this project are **not legal certification**. They do not certify compliance with HIPAA, GDPR, PCI DSS, ISO 27001, HITRUST, SOC 2, 21 CFR Part 11 or any other law, regulation, standard or contractual obligation. No output from BioShield may be represented to a regulator, auditor, customer or court as proof of compliance.

## What the tooling does

- Records synthetic evidence items against internal control identifiers.
- Shows which checklist items have supporting documents in the sandbox.
- Generates sample reports with methodology, confidence values and reviewer status.
- Keeps an audit trail of actions performed in the demonstration workspace.

## What the tooling does not do

- Interpret legal obligations for your organization.
- Validate that a control operates effectively over time.
- Replace qualified privacy counsel, auditors or compliance officers.
- Certify systems, vendors, processes or personnel.
- Authorize handling of real patient data.

## Required human review

Every finding and checklist item should be reviewed by a qualified person. Reviewers must:

1. Confirm the context and classification of each candidate entity.
2. Verify that masking preserves the intended utility of synthetic content.
3. Document rejections and overrides with clear rationale.
4. Treat automated scores as signals, not conclusions.
5. Escalate uncertain cases to an appropriate professional.

## Sample report limitations

Reports under `docs/sample-reports/` are labelled SAMPLE and contain fabricated records only. They demonstrate structure and terminology; they make no claim about real patients, real systems or real organizational compliance. Generated report metadata should remain in `sample` status until an authorized human approves a separate, organization-specific report.

## Synthetic data boundary

All names, identifiers, dates, organizations, email addresses and network addresses in BioShield are invented. Email domains use `.invalid`, and sample IPs use documentation ranges. Do not upload real clinical records to this environment, and do not replace sample content with patient data.

## Recommended language for downstream use

When sharing outputs, use wording such as: "Automated checklist evidence generated in a synthetic demonstration environment for internal review; not a certification of compliance."

## License note

This disclaimer is provided with the MIT-licensed project and does not create a warranty, guarantee or professional relationship. Copyright (c) 2026 n j bala manikantan.
