from pathlib import Path
from xml.sax.saxutils import escape

from docx import Document
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

BASE_DIR = Path(__file__).resolve().parent
SUMMARY_TXT = BASE_DIR / "synthetic_patient_summary.txt"
NOTES_TXT = BASE_DIR / "synthetic_clinical_notes.txt"
SUMMARY_PDF = BASE_DIR / "synthetic_patient_summary.pdf"
NOTES_DOCX = BASE_DIR / "synthetic_clinical_notes.docx"


def read_lines(path):
    if not path.exists():
        raise SystemExit(f"Missing source file: {path}")
    return path.read_text(encoding="utf-8").splitlines()


def build_pdf():
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "BioShieldSampleTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        textColor="#10233f",
        spaceAfter=6,
    )
    notice_style = ParagraphStyle(
        "BioShieldSampleNotice",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor="#8a6c2b",
        spaceAfter=10,
    )
    body_style = ParagraphStyle(
        "BioShieldSampleBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=5,
    )
    document = SimpleDocTemplate(
        str(SUMMARY_PDF),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="SAMPLE Synthetic Patient Summary",
        author="BioShield",
        subject="Fabricated demonstration data only",
    )
    story = [
        Paragraph("SAMPLE - SYNTHETIC PATIENT SUMMARY", title_style),
        Paragraph("FABRICATED DATA ONLY. This document contains no real patient information.", notice_style),
    ]
    for line in read_lines(SUMMARY_TXT):
        if line.strip():
            story.append(Paragraph(escape(line), body_style))
        else:
            story.append(Spacer(1, 6))
    document.build(story)
    return SUMMARY_PDF


def build_docx():
    document = Document()
    document.core_properties.title = "SAMPLE Synthetic Clinical Notes"
    document.core_properties.author = "BioShield"
    document.core_properties.subject = "Fabricated demonstration data only"
    document.add_heading("SAMPLE - SYNTHETIC CLINICAL NOTES", level=0)
    notice = document.add_paragraph()
    notice_run = notice.add_run("FABRICATED DATA ONLY. This document contains no real patient information.")
    notice_run.bold = True
    for line in read_lines(NOTES_TXT):
        if line.strip():
            document.add_paragraph(line)
        else:
            document.add_paragraph("")
    document.save(str(NOTES_DOCX))
    return NOTES_DOCX


def main():
    pdf_path = build_pdf()
    docx_path = build_docx()
    print(f"Created sample PDF: {pdf_path}")
    print(f"Created sample DOCX: {docx_path}")
    print("All generated content is synthetic and must never be replaced with real patient records.")


if __name__ == "__main__":
    main()
