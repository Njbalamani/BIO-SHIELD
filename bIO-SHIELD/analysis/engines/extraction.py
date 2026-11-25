import io


def _normalize_extension(extension):
    if extension is None:
        return ""
    value = str(extension).strip().lower()
    if not value:
        return ""
    if not value.startswith("."):
        value = "." + value
    return value


def _as_bytes(raw_bytes):
    if isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        return bytes(raw_bytes)
    raise ValueError("Document content must be bytes.")


def _metadata(extension, text, **extra):
    metadata = {"extension": extension, "char_count": len(text)}
    metadata.update(extra)
    return metadata


def extract_text(raw_bytes, extension):
    raw = _as_bytes(raw_bytes)
    ext = _normalize_extension(extension)
    if ext == ".txt":
        if b"\x00" in raw:
            raise ValueError("TXT document contains invalid content.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("TXT document is not valid UTF-8.") from exc
        return text, _metadata(ext, text)
    if ext == ".pdf":
        try:
            from pypdf import PdfReader
        except Exception as exc:
            raise ValueError("PDF extraction requires pypdf.") from exc
        try:
            reader = PdfReader(io.BytesIO(raw))
            if reader.is_encrypted:
                reader.decrypt("")
            pages = [page.extract_text() or "" for page in reader.pages]
            text = "\n\n".join(pages)
            page_count = len(reader.pages)
        except Exception as exc:
            raise ValueError("Unable to extract text from PDF.") from exc
        return text, _metadata(ext, text, page_count=page_count)
    if ext == ".docx":
        try:
            from docx import Document
        except Exception as exc:
            raise ValueError("DOCX extraction requires python-docx.") from exc
        try:
            document = Document(io.BytesIO(raw))
            paragraphs = [paragraph.text or "" for paragraph in document.paragraphs]
            text = "\n".join(paragraphs)
            paragraph_count = len(paragraphs)
        except Exception as exc:
            raise ValueError("Unable to extract text from DOCX.") from exc
        return text, _metadata(ext, text, paragraph_count=paragraph_count)
    raise ValueError("Unsupported document extension; allowed extensions are .pdf, .txt, .docx.")
