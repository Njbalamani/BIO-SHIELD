import hashlib
import io
import zipfile
from pathlib import Path

_ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx"}
_REQUIRED_DOCX_PARTS = {"[Content_Types].xml", "word/document.xml"}


def _extension_from_uploaded(uploaded):
    name = getattr(uploaded, "name", None)
    if not name and isinstance(uploaded, str):
        name = uploaded
    if not name:
        return ""
    return Path(str(name)).suffix.lower()


def _read_upload(uploaded, max_bytes):
    if uploaded is None:
        raise ValueError("Uploaded document is empty.")
    try:
        limit = int(max_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("Maximum upload size must be a positive integer.") from exc
    if limit <= 0:
        raise ValueError("Maximum upload size must be a positive integer.")
    declared_size = getattr(uploaded, "size", None)
    if isinstance(declared_size, int) and declared_size > limit:
        raise ValueError(f"Document exceeds maximum size of {limit} bytes.")
    if isinstance(uploaded, (bytes, bytearray, memoryview)):
        raw = bytes(uploaded)
    else:
        reader = getattr(uploaded, "read", None)
        if not callable(reader):
            raise ValueError("Uploaded document is empty.")
        raw = reader(limit + 1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        elif isinstance(raw, (bytearray, memoryview)):
            raw = bytes(raw)
        elif not isinstance(raw, bytes):
            raise ValueError("Uploaded document could not be read.")
    if not raw:
        raise ValueError("Uploaded document is empty.")
    if len(raw) > limit:
        raise ValueError(f"Document exceeds maximum size of {limit} bytes.")
    return raw


def validate_document_upload(uploaded, max_bytes):
    extension = _extension_from_uploaded(uploaded)
    if extension not in _ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported document extension; allowed extensions are .pdf, .txt, .docx.")
    raw_bytes = _read_upload(uploaded, max_bytes)
    digest = hashlib.sha256(raw_bytes).hexdigest()
    if extension == ".txt":
        if b"\x00" in raw_bytes:
            raise ValueError("TXT document contains null bytes.")
        try:
            raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("TXT document is not valid UTF-8.") from exc
    elif extension == ".pdf":
        if not raw_bytes.startswith(b"%PDF-"):
            raise ValueError("PDF document has an invalid header.")
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:
                names = set(archive.namelist())
                if not _REQUIRED_DOCX_PARTS.issubset(names):
                    raise ValueError("DOCX document is missing required zip structure.")
                if archive.testzip() is not None:
                    raise ValueError("DOCX document zip structure is corrupt.")
        except ValueError:
            raise
        except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
            raise ValueError("DOCX document has an invalid zip structure.") from exc
    return raw_bytes, extension, digest
