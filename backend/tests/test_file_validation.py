"""Docspector File Upload Validation Test Suite (Milestone 8).

Validates security invariants and bounded-memory streaming behavior:
- Supported types: PDF, PNG, UTF-8 TXT
- Maximum file size: 25 MiB (26,214,400 bytes)
- Case-insensitive extension matching
- MIME type verification & extension alignment
- Magic byte inspection (PDF: %PDF-, PNG: \\x89PNG\\r\\n\\x1a\\n)
- Incremental UTF-8 validation across chunk boundaries
- Path traversal rejection
- Cryptographically random storage key generation
- Ephemeral temporary staging and cleanup on failure
- Strict 0-byte empty file rejection policy
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile

import pytest

from app.services.file_validation import (
    DEFAULT_CHUNK_SIZE_BYTES,
    ERROR_CODE_EMPTY_FILE,
    ERROR_CODE_FILE_TOO_LARGE,
    ERROR_CODE_INVALID_FILENAME,
    ERROR_CODE_INVALID_MAGIC_BYTES,
    ERROR_CODE_INVALID_UTF8,
    ERROR_CODE_MIME_EXTENSION_MISMATCH,
    ERROR_CODE_UNSUPPORTED_EXTENSION,
    ERROR_CODE_UNSUPPORTED_MIME_TYPE,
    MAX_FILE_SIZE_BYTES,
    FileValidationError,
    generate_storage_key,
    validate_and_stage_upload,
    validate_file_bytes,
    validate_file_stream,
    validate_filename,
    validate_mime_type,
)

# Synthetic test payloads
VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
VALID_TXT_BYTES = "Docspector Synthetic Investigation Case #2026-44\nStatus: ACTIVE\nSummary: Verified custody chain.\n".encode("utf-8")


def test_file_01_valid_pdf_accepted():
    """FILE-01: Valid synthetic PDF with %PDF- header is accepted."""
    result = validate_file_bytes(
        data=VALID_PDF_BYTES,
        filename="investigation_report.pdf",
        content_type="application/pdf",
    )
    assert result.extension == ".pdf"
    assert result.media_type == "application/pdf"
    assert result.size_bytes == len(VALID_PDF_BYTES)
    assert result.storage_key.endswith(".pdf")
    assert len(result.sha256_checksum) == 64


def test_file_02_valid_png_accepted():
    """FILE-02: Valid synthetic PNG with standard PNG magic header is accepted."""
    result = validate_file_bytes(
        data=VALID_PNG_BYTES,
        filename="evidence_photo.png",
        content_type="image/png",
    )
    assert result.extension == ".png"
    assert result.media_type == "image/png"
    assert result.size_bytes == len(VALID_PNG_BYTES)
    assert result.storage_key.endswith(".png")
    assert len(result.sha256_checksum) == 64


def test_file_03_valid_utf8_txt_accepted():
    """FILE-03: Valid plain UTF-8 text file is accepted."""
    result = validate_file_bytes(
        data=VALID_TXT_BYTES,
        filename="officer_notes.txt",
        content_type="text/plain",
    )
    assert result.extension == ".txt"
    assert result.media_type == "text/plain"
    assert result.size_bytes == len(VALID_TXT_BYTES)
    assert result.storage_key.endswith(".txt")


def test_file_04_pdf_with_wrong_extension_rejected():
    """FILE-04: PDF content with .png extension is rejected by signature validator."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=VALID_PDF_BYTES,
            filename="fake_image.png",
            content_type="image/png",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES
    assert exc_info.value.http_status_code == 400


def test_file_05_png_with_wrong_extension_rejected():
    """FILE-05: PNG content with .pdf extension is rejected by signature validator."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=VALID_PNG_BYTES,
            filename="fake_report.pdf",
            content_type="application/pdf",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES
    assert exc_info.value.http_status_code == 400


def test_file_06_txt_with_invalid_utf8_rejected():
    """FILE-06: Text file containing non-UTF8 binary bytes is rejected."""
    invalid_utf8_bytes = b"Docspector header\n\x80\x81\xff\xfe corrupt binary data"
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=invalid_utf8_bytes,
            filename="bad_notes.txt",
            content_type="text/plain",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_UTF8
    assert exc_info.value.http_status_code == 400


def test_file_07_pdf_with_incorrect_magic_bytes_rejected():
    """FILE-07: File with .pdf extension but corrupted/non-PDF header is rejected."""
    corrupted_pdf = b"%NOTPDF-corrupt-payload-00123"
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=corrupted_pdf,
            filename="corrupted.pdf",
            content_type="application/pdf",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES
    assert exc_info.value.http_status_code == 400


def test_file_08_png_with_incorrect_magic_bytes_rejected():
    """FILE-08: File with .png extension but invalid magic bytes is rejected."""
    corrupted_png = b"\x00\x01\x02\x03\x04\x05\x06\x07fake-png-bytes"
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=corrupted_png,
            filename="corrupted.png",
            content_type="image/png",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES
    assert exc_info.value.http_status_code == 400


def test_file_09_mime_type_mismatch_rejected():
    """FILE-09: Extension and Content-Type mismatch is rejected."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=VALID_PDF_BYTES,
            filename="document.pdf",
            content_type="image/png",  # Mismatched MIME
        )
    assert exc_info.value.code == ERROR_CODE_MIME_EXTENSION_MISMATCH
    assert exc_info.value.http_status_code == 415


def test_file_10_unsupported_mime_type_rejected():
    """FILE-10: Unsupported Content-Type is rejected with HTTP 415."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_bytes(
            data=VALID_PDF_BYTES,
            filename="document.pdf",
            content_type="application/x-msdownload",
        )
    assert exc_info.value.code == ERROR_CODE_UNSUPPORTED_MIME_TYPE
    assert exc_info.value.http_status_code == 415


def test_file_11_unsupported_extension_rejected():
    """FILE-11: Unsupported file extensions (.exe, .docx, .sh, .py) are rejected."""
    for bad_name in ["script.py", "malware.exe", "document.docx", "deploy.sh"]:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(bad_name)
        assert exc_info.value.code == ERROR_CODE_UNSUPPORTED_EXTENSION
        assert exc_info.value.http_status_code == 415


def test_file_12_case_insensitive_valid_extensions_accepted():
    """FILE-12: Upper and mixed-case valid extensions (.PDF, .PNG, .Txt) are accepted."""
    test_cases = [
        ("EVIDENCE.PDF", VALID_PDF_BYTES, ".pdf", "application/pdf"),
        ("Scan.PNG", VALID_PNG_BYTES, ".png", "image/png"),
        ("NOTES.Txt", VALID_TXT_BYTES, ".txt", "text/plain"),
    ]
    for filename, payload, expected_ext, expected_mime in test_cases:
        res = validate_file_bytes(data=payload, filename=filename)
        assert res.extension == expected_ext
        assert res.media_type == expected_mime


def test_file_13_file_larger_than_25_mib_rejected():
    """FILE-13: File exceeding 25 MiB canonical limit is rejected with HTTP 413."""
    # Simulate a stream that exceeds MAX_FILE_SIZE_BYTES without allocating 25MB in RAM
    class OversizedPdfStream(io.RawIOBase):
        def __init__(self, target_size: int):
            self.target_size = target_size
            self.bytes_read = 0
            self.header = b"%PDF-1.7\n"

        def read(self, size: int = -1) -> bytes:
            if self.bytes_read >= self.target_size:
                return b""
            if size is None or size < 0:
                size = 64 * 1024
            size = min(size, self.target_size - self.bytes_read)
            if self.bytes_read == 0 and len(self.header) <= size:
                chunk = self.header + b"A" * (size - len(self.header))
            else:
                chunk = b"A" * size
            self.bytes_read += len(chunk)
            return chunk

    oversized_stream = OversizedPdfStream(MAX_FILE_SIZE_BYTES + 1)
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_stream(
            stream=oversized_stream,
            filename="large_case_file.pdf",
            content_type="application/pdf",
        )
    assert exc_info.value.code == ERROR_CODE_FILE_TOO_LARGE
    assert exc_info.value.http_status_code == 413


def test_file_14_file_exactly_at_25_mib_boundary_accepted():
    """FILE-14: File exactly at the 25 MiB boundary (26,214,400 bytes) is accepted."""
    class BoundaryPdfStream(io.RawIOBase):
        def __init__(self, target_size: int):
            self.target_size = target_size
            self.bytes_read = 0
            self.header = b"%PDF-1.7\n"

        def read(self, size: int = -1) -> bytes:
            if self.bytes_read >= self.target_size:
                return b""
            if size is None or size < 0:
                size = 64 * 1024
            size = min(size, self.target_size - self.bytes_read)
            if self.bytes_read == 0 and len(self.header) <= size:
                chunk = self.header + b"0" * (size - len(self.header))
            else:
                chunk = b"0" * size
            self.bytes_read += len(chunk)
            return chunk

    boundary_stream = BoundaryPdfStream(MAX_FILE_SIZE_BYTES)
    res = validate_file_stream(
        stream=boundary_stream,
        filename="boundary_document.pdf",
        content_type="application/pdf",
    )
    assert res.size_bytes == MAX_FILE_SIZE_BYTES
    assert res.extension == ".pdf"


def test_file_15_path_traversal_filenames_rejected():
    """FILE-15: Malicious path traversal sequences in filenames are strictly rejected."""
    traversal_filenames = [
        "../../evil.pdf",
        "..\\..\\evil.pdf",
        "/etc/passwd.pdf",
        "C:\\Windows\\System32\\driver.png",
        "nested/dir/notes.txt",
        "..\\notes.txt",
    ]
    for malicious_name in traversal_filenames:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(malicious_name)
        assert exc_info.value.code == ERROR_CODE_INVALID_FILENAME
        assert exc_info.value.http_status_code == 400


def test_file_16_original_filename_not_used_as_storage_key():
    """FILE-16: Storage key is generated with cryptographically random identifiers."""
    original_name = "secret_investigation_document_2026.pdf"
    key1 = generate_storage_key(".pdf")
    key2 = generate_storage_key(".pdf")

    assert key1 != key2
    assert "secret_investigation" not in key1
    assert key1.endswith(".pdf")
    assert key2.endswith(".pdf")

    res = validate_file_bytes(data=VALID_PDF_BYTES, filename=original_name)
    assert res.storage_key != original_name
    assert original_name not in res.storage_key
    assert res.storage_key.endswith(".pdf")


def test_file_17_rejected_upload_cleans_up_staged_temporary_files():
    """FILE-17: Atomic staging cleans up ephemeral files immediately on validation failure."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage_dir = Path(tmp_dir)

        # Attempt to upload an invalid PDF (corrupt magic bytes)
        corrupted_stream = io.BytesIO(b"NOT_A_VALID_PDF_HEADER_DATA")

        with pytest.raises(FileValidationError) as exc_info:
            validate_and_stage_upload(
                stream=corrupted_stream,
                filename="failed_upload.pdf",
                target_storage_dir=storage_dir,
                content_type="application/pdf",
            )
        assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES

        # Verify no files remain in the storage directory
        remaining_files = list(storage_dir.iterdir())
        assert len(remaining_files) == 0


def test_file_18_valid_utf8_split_across_chunks_accepted():
    """FILE-18: Multi-byte UTF-8 character split exactly across chunk boundaries is accepted."""
    # Chunk size is small for testing boundary behavior
    chunk_size = 8
    # UTF-8 character '€' is 3 bytes (0xE2 0x82 0xAC), '😀' is 4 bytes (0xF0 0x9F 0x98 0x80)
    # Position '€' so byte 1 is at index 7 (end of chunk 1) and bytes 2-3 are at index 8-9 (start of chunk 2)
    prefix = b"1234567"  # 7 bytes
    euro_bytes = "€".encode("utf-8")  # 3 bytes: b'\xe2\x82\xac'
    suffix = " investigation notes with emoji 😀".encode("utf-8")
    payload = prefix + euro_bytes + suffix

    stream = io.BytesIO(payload)
    res = validate_file_stream(
        stream=stream,
        filename="multibyte_notes.txt",
        content_type="text/plain",
        chunk_size_bytes=chunk_size,
    )
    assert res.extension == ".txt"
    assert res.size_bytes == len(payload)


def test_file_19_malformed_utf8_split_across_chunks_rejected():
    """FILE-19: Incomplete multi-byte sequence truncated at end of file is rejected."""
    # Incomplete UTF-8 sequence (first 2 bytes of 3-byte '€' without 3rd byte)
    incomplete_utf8 = b"Valid ASCII content prefix \xe2\x82"

    stream = io.BytesIO(incomplete_utf8)
    with pytest.raises(FileValidationError) as exc_info:
        validate_file_stream(
            stream=stream,
            filename="truncated_utf8.txt",
            content_type="text/plain",
            chunk_size_bytes=8,
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_UTF8
    assert exc_info.value.http_status_code == 400


def test_file_20_empty_file_policy_rejection():
    """FILE-20: Empty files (0 bytes) are rejected per documented policy."""
    for empty_name, mime in [
        ("empty.pdf", "application/pdf"),
        ("empty.png", "image/png"),
        ("empty.txt", "text/plain"),
    ]:
        with pytest.raises(FileValidationError) as exc_info:
            validate_file_bytes(data=b"", filename=empty_name, content_type=mime)
        assert exc_info.value.code == ERROR_CODE_EMPTY_FILE
        assert exc_info.value.http_status_code == 400


def test_security_null_byte_in_filename_rejected():
    """Security negative: Null byte injection in filename is rejected."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_filename("report\x00.pdf")
    assert exc_info.value.code == ERROR_CODE_INVALID_FILENAME
    assert exc_info.value.http_status_code == 400


def test_security_double_extension_executable_rejected():
    """Security negative: Double extension like report.pdf.exe is rejected."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_filename("report.pdf.exe")
    assert exc_info.value.code == ERROR_CODE_UNSUPPORTED_EXTENSION
    assert exc_info.value.http_status_code == 415


def test_security_missing_extension_rejected():
    """Security negative: File without extension is rejected."""
    with pytest.raises(FileValidationError) as exc_info:
        validate_filename("README")
    assert exc_info.value.code == ERROR_CODE_UNSUPPORTED_EXTENSION
    assert exc_info.value.http_status_code == 415


def test_security_blank_filename_rejected():
    """Security negative: Empty or blank filename is rejected."""
    for blank_name in ["", "   ", "\t\n"]:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(blank_name)
        assert exc_info.value.code == ERROR_CODE_INVALID_FILENAME
        assert exc_info.value.http_status_code == 400


def test_staging_success_moves_file_to_final_storage_key():
    """Verify that successful atomic staging places file under the randomized storage_key."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage_dir = Path(tmp_dir)
        stream = io.BytesIO(VALID_PDF_BYTES)

        result, staged_path = validate_and_stage_upload(
            stream=stream,
            filename="valid_evidence.pdf",
            target_storage_dir=storage_dir,
            content_type="application/pdf",
        )

        assert staged_path.exists()
        assert staged_path.name == result.storage_key
        assert staged_path.read_bytes() == VALID_PDF_BYTES
        # Verify no .tmp files remain
        tmp_files = list(storage_dir.glob("*.tmp"))
        assert len(tmp_files) == 0
