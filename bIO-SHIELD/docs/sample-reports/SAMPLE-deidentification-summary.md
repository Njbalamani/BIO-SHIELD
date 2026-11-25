# SAMPLE REPORT - Synthetic De-identification Summary

**Status:** SAMPLE ONLY · **Environment:** Synthetic demonstration · **Generated:** 2026-04-07

This report is fabricated for interface demonstration. It contains no real patient data and makes no claim about any real person, organization or system. It is not legal certification.

## Scope

| Item | Value |
| --- | --- |
| Organization | Northwind Example Clinic (fictional) |
| Document set | Four fabricated summaries and notes |
| Review window | 2026-02-11 to 2026-04-06 |
| Data class | Synthetic only |

## Methodology

1. Text was extracted from fabricated TXT sources.
2. Rule-based detection proposed candidate identifiers.
3. Model-assisted detection proposed additional entity classes.
4. Candidate offsets were normalized and masked with typed tokens.
5. A fictional reviewer recorded accept or reject decisions.

## Illustrative results

| Entity class | Candidates | Accepted | Masked token |
| --- | ---: | ---: | --- |
| PERSON | 8 | 8 | `[PERSON]` |
| ID | 6 | 6 | `[ID]` |
| DATE | 5 | 4 | `[DATE]` |
| EMAIL | 4 | 4 | `[EMAIL]` |
| ORG | 4 | 3 | `[ORG]` |

## Review notes

- All source names such as Avery Placeholder and Casey Testcase are invented.
- All email addresses use `example.invalid`.
- One DATE candidate was rejected because it represented a fabricated encounter date with no identifier value.
- One ORG candidate was generalized to a class label.

## Limitations

Automated detection can produce false positives and false negatives. These numbers demonstrate report structure only. They must not be used to estimate performance on real clinical data or to claim compliance with any standard.
