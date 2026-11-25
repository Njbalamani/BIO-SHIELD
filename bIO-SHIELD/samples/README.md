# Synthetic samples

Every file in this directory is fabricated for demonstration and testing. Names, identifiers, dates, organizations, addresses and domains are placeholders. Email addresses use the reserved `.invalid` top-level domain. No file here contains, describes or derives from a real patient record.

| File | Purpose |
| --- | --- |
| `synthetic_patient_summary.txt` | Fabricated patient-style summary for text scanning |
| `synthetic_clinical_notes.txt` | Fabricated clinical narrative with multiple placeholder entities |
| `synthetic_access_events.csv` | Fabricated access-event rows using documentation IP ranges |
| `generate_synthetic_documents.py` | Builds PDF and DOCX versions from the text files |

## Generate binary samples

From the project root:

```powershell
python samples/generate_synthetic_documents.py
```

The script writes `samples/synthetic_patient_summary.pdf` and `samples/synthetic_clinical_notes.docx`. It uses paths relative to its own location, so it is safe to invoke from any working directory.

## Safe use

- Use these files for local demos, tests and screenshots only.
- Do not replace any line with real clinical content.
- Keep `SYNTHETIC_DATA_ONLY=True` in `.env` for demonstration deployments.
- Automated checklists in this project are decision support, not legal certification.
