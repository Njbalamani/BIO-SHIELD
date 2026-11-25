# SAMPLE REPORT - Synthetic Access Review

**Status:** SAMPLE ONLY · **Environment:** Synthetic demonstration · **Generated:** 2026-04-09

This report is a fabricated example created to demonstrate audit reporting. Every actor, document, address and timestamp below is invented. It contains no real patient claims and is not legal certification.

## Scope

| Item | Value |
| --- | --- |
| Source | `samples/synthetic_access_events.csv` |
| Event count | Ten fabricated rows |
| Window | 2026-02-11 to 2026-04-07 |
| IP ranges | Documentation-only ranges |

## Illustrative summary

| Event type | Count | Outcome |
| --- | ---: | --- |
| view | 2 | allowed |
| scan | 2 | allowed |
| review | 1 | allowed |
| upload | 1 | allowed |
| export | 1 | allowed with manual review |
| login_attempt | 1 | denied |
| download | 1 | allowed |
| audit | 1 | allowed |

## Notable fabricated signals

- `EVT-SYN-0005` shows a denied login attempt for `unknown.actor@example.invalid` with a repeated-failure signal.
- `EVT-SYN-0008` shows an export action flagged for manual review in the synthetic workflow.
- No row references a real user, real document or real network asset.

## Demonstrated controls

- Request identifiers can be correlated with audit entries.
- Access events record actor, event type, resource, source and outcome.
- Reviewer decisions are separate from automated scan results.
- Reports retain sample status until a human approves a real, organization-specific version.

## Limitations

This sample does not evidence effective control operation. It is illustrative content only. Do not present it as an audit finding, certification or compliance evidence.
