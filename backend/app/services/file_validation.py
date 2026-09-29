"""Docspector secure file upload validation service.

Inspect. Verify. Trust.

This module provides stream-based, bounded-memory validation of uploaded files
against strict security invariants:
1. Canonical file size limit (25 MiB max).
2. Strict extension whitelist (.pdf, .png, .txt) with case-insensitivity.
3. Content-Type / MIME type verification matching expected extension.
4. Magic byte signature verification for binary formats (PDF, PNG).
5. Incremental UTF-8 validation across chunk boundaries for plain text.
6. Path traversal and malicious filename protection.
7. Cryptographically random private storage key generation.
8. Bounded memory consumption with stream-based processing.
9. Automatic cleanup of staged temporary files upon validation failure.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass
import hashlib
import io
from pathlib import Path, PureWindowsPath
import re
import secrets
from typing import IO, Any
import uuid

# Canonical limits and constants
MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # Exactly 25 MiB (26,214,400 bytes)
DEFAULT_CHUNK_SIZE_BYTES: int = 64 * 1024  # 64 KiB bounded read chunk

# Supported extensions (canonical lowercase with leading dot)
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".pdf", ".png", ".txt"})

# Expected MIME / Content-Type mappings
MIME_TYPE_MAP: dict[str, str] = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".txt": "text/plain",
}

# Magic byte signatures
PDF_MAGIC_BYTES: bytes = b"%PDF-"  # Standard PDF file header (5 bytes)
PNG_MAGIC_BYTES: bytes = b"\x89PNG\r\n\x1a\n"  # Exact 8-byte PNG header

# Stable validation error codes
ERROR_CODE_FILE_TOO_LARGE: str = "FILE_TOO_LARGE"
ERROR_CODE_UNSUPPORTED_EXTENSION: str = "UNSUPPORTED_EXTENSION"
ERROR_CODE_UNSUPPORTED_MIME_TYPE: str = "UNSUPPORTED_MIME_TYPE"
ERROR_CODE_MIME_EXTENSION_MISMATCH: str = "MIME_EXTENSION_MISMATCH"
ERROR_CODE_INVALID_MAGIC_BYTES: str = "INVALID_MAGIC_BYTES"
ERROR_CODE_INVALID_UTF8: str = "INVALID_UTF8"
ERROR_CODE_INVALID_FILENAME: str = "INVALID_FILENAME"
ERROR_CODE_EMPTY_FILE: str = "EMPTY_FILE"


class FileValidationError(Exception):
    """Structured exception raised when file upload validation fails."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status_code = http_status_code
        self.details = details or {}


@dataclass(frozen=True)
class ValidationResult:
    """Structured metadata returned after successful file validation."""

    original_filename: str
    sanitized_filename: str
    extension: str
    media_type: str
    size_bytes: int
    sha256_checksum: str
    storage_key: str


def generate_storage_key(extension: str) -> str:
    """Generate a cryptographically secure, unpredictable private storage key.

    Uses UUIDv4 and random hex entropy to ensure filenames cannot be guessed
    or derived from untrusted client metadata.
    """
    ext = extension.lower() if extension.startswith(".") else f".{extension.lower()}"
    token = secrets.token_hex(8)
    return f"{uuid.uuid4().hex}_{token}{ext}"


def safe_resolve_storage_path(storage_dir: Path | str, storage_key: str) -> Path:
    """Safely resolve a storage key against a storage directory, preventing directory traversal.

    Guarantees:
    - Storage key is a pure filename with no directory components.
    - Resolved path stays strictly within the canonical storage directory.
    - Rejects path traversal, drive letters, and escape attempts.
    """
    if not storage_key or not isinstance(storage_key, str) or not storage_key.strip():
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Storage key cannot be empty.",
            http_status_code=400,
        )

    # Check for path traversal or separator characters in storage_key
    if "/" in storage_key or "\\" in storage_key or ".." in storage_key:
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Storage key contains illegal path traversal characters.",
            http_status_code=400,
            details={"storage_key": storage_key},
        )

    base_dir = Path(storage_dir).resolve()
    target_path = (base_dir / storage_key).resolve()

    try:
        # Verify target is relative to base_dir
        target_path.relative_to(base_dir)
    except ValueError as exc:
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Storage key resolves outside authorized private storage root.",
            http_status_code=400,
            details={"storage_key": storage_key},
        ) from exc

    return target_path


def validate_filename(filename: str | None) -> tuple[str, str]:
    """Validate and sanitize untrusted client filename.

    Enforces:
    - Non-empty, non-whitespace filename.
    - No null bytes (\x00).
    - No directory traversal sequences (../, ..\\, leading slashes, drive letters).
    - Valid, supported extension from ALLOWED_EXTENSIONS (case-insensitive).

    Returns:
        (sanitized_filename, normalized_extension)

    Raises:
        FileValidationError: If filename is malformed, dangerous, or unsupported.
    """
    if not filename or not isinstance(filename, str) or not filename.strip():
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Filename cannot be empty or blank.",
            http_status_code=400,
            details={"filename": filename},
        )

    raw_filename = filename.strip()

    # Reject null bytes
    if "\x00" in raw_filename:
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Filename contains illegal null byte character.",
            http_status_code=400,
            details={"filename": raw_filename},
        )

    # Check for path traversal / directory separator attempts
    # Check both POSIX and Windows path separators
    if (
        "/" in raw_filename
        or "\\" in raw_filename
        or ".." in raw_filename
        or re.search(r"^[a-zA-Z]:", raw_filename)  # Drive letter (C:)
    ):
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Filename must not contain path traversal sequences or directory separators.",
            http_status_code=400,
            details={"filename": raw_filename},
        )

    # Extract clean basename using standard path normalization
    sanitized_name = Path(raw_filename).name
    # Double check for Windows path peculiarities
    sanitized_name = PureWindowsPath(sanitized_name).name

    if not sanitized_name:
        raise FileValidationError(
            code=ERROR_CODE_INVALID_FILENAME,
            message="Invalid filename.",
            http_status_code=400,
            details={"filename": raw_filename},
        )

    # Extract extension
    suffix_match = re.search(r"(\.[a-zA-Z0-9]+)$", sanitized_name)
    if not suffix_match:
        raise FileValidationError(
            code=ERROR_CODE_UNSUPPORTED_EXTENSION,
            message="File is missing a valid extension.",
            http_status_code=415,
            details={"filename": sanitized_name},
        )

    extension = suffix_match.group(1).lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            code=ERROR_CODE_UNSUPPORTED_EXTENSION,
            message=f"File extension '{extension}' is not supported. Allowed: {sorted(ALLOWED_EXTENSIONS)}",
            http_status_code=415,
            details={
                "filename": sanitized_name,
                "extension": extension,
                "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
            },
        )

    return sanitized_name, extension


def validate_mime_type(
    content_type: str | None,
    expected_extension: str,
) -> str:
    """Validate client-provided MIME / Content-Type header.

    Enforces:
    - If provided, MIME type must be known and match the file extension.
    - If None/missing, defaults to the canonical MIME type for the extension.

    Returns:
        Canonical media_type string.

    Raises:
        FileValidationError: If MIME type is unsupported or conflicts with extension.
    """
    expected_mime = MIME_TYPE_MAP.get(expected_extension.lower())
    if not expected_mime:
        raise FileValidationError(
            code=ERROR_CODE_UNSUPPORTED_EXTENSION,
            message=f"No known MIME type mapping for extension '{expected_extension}'.",
            http_status_code=415,
            details={"extension": expected_extension},
        )

    if content_type is None or not content_type.strip():
        # Fall back to canonical expected MIME type when client omits Content-Type
        return expected_mime

    # Normalize client Content-Type (strip charset/parameters and whitespace)
    normalized_mime = content_type.split(";")[0].strip().lower()

    # Check if normalized_mime is an allowed MIME type in our system
    allowed_mimes = set(MIME_TYPE_MAP.values())
    if normalized_mime not in allowed_mimes:
        raise FileValidationError(
            code=ERROR_CODE_UNSUPPORTED_MIME_TYPE,
            message=f"MIME type '{content_type}' is unsupported.",
            http_status_code=415,
            details={"content_type": content_type, "allowed_mimes": sorted(allowed_mimes)},
        )

    if normalized_mime != expected_mime:
        raise FileValidationError(
            code=ERROR_CODE_MIME_EXTENSION_MISMATCH,
            message=(
                f"MIME type '{normalized_mime}' does not match expected "
                f"'{expected_mime}' for extension '{expected_extension}'."
            ),
            http_status_code=415,
            details={
                "provided_mime": normalized_mime,
                "expected_mime": expected_mime,
                "extension": expected_extension,
            },
        )

    return expected_mime


def validate_file_stream(
    stream: IO[bytes],
    filename: str,
    content_type: str | None = None,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
    chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> ValidationResult:
    """Validate a file stream using bounded-memory chunked reading.

    Invariants checked:
    1. Filename is clean, path-traversal free, and has an allowed extension (.pdf, .png, .txt).
    2. Content-Type header (if provided) matches the extension.
    3. Stream is non-empty (0 bytes is rejected per policy).
    4. Total size <= max_size_bytes (25 MiB). Stream reading terminates early if exceeded.
    5. Content matches magic byte signatures (PDF, PNG) or strict incremental UTF-8 (TXT).
    6. SHA-256 checksum is computed over the entire stream.

    Returns:
        ValidationResult with validated metadata and random storage key.

    Raises:
        FileValidationError: On any validation failure.
    """
    sanitized_filename, extension = validate_filename(filename)
    media_type = validate_mime_type(content_type, extension)

    total_size = 0
    sha256 = hashlib.sha256()

    header_bytes = bytearray()
    header_needed = len(PNG_MAGIC_BYTES)  # 8 bytes is sufficient for PDF (5) & PNG (8)

    # For TXT files: use incremental UTF-8 decoder with strict error handling
    txt_decoder = (
        codecs.getincrementaldecoder("utf-8")(errors="strict")
        if extension == ".txt"
        else None
    )

    while True:
        chunk = stream.read(chunk_size_bytes)
        if not chunk:
            break

        chunk_len = len(chunk)
        total_size += chunk_len

        # Terminate immediately if file exceeds maximum size limit
        if total_size > max_size_bytes:
            raise FileValidationError(
                code=ERROR_CODE_FILE_TOO_LARGE,
                message=f"File exceeds maximum allowed size of {max_size_bytes} bytes (25 MiB).",
                http_status_code=413,
                details={
                    "max_size_bytes": max_size_bytes,
                    "exceeded_at_bytes": total_size,
                },
            )

        sha256.update(chunk)

        # Accumulate header bytes for magic signature inspection
        if len(header_bytes) < header_needed:
            needed = header_needed - len(header_bytes)
            header_bytes.extend(chunk[:needed])

        # Validate incremental UTF-8 for text files
        if txt_decoder is not None:
            try:
                txt_decoder.decode(chunk, final=False)
            except UnicodeDecodeError as exc:
                raise FileValidationError(
                    code=ERROR_CODE_INVALID_UTF8,
                    message="Text file contains malformed or non-UTF-8 byte sequences.",
                    http_status_code=400,
                    details={"error": str(exc)},
                ) from exc

    # Finalize TXT decoding
    if txt_decoder is not None:
        try:
            txt_decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise FileValidationError(
                code=ERROR_CODE_INVALID_UTF8,
                message="Text file contains incomplete or malformed UTF-8 byte sequence at end of file.",
                http_status_code=400,
                details={"error": str(exc)},
            ) from exc

    # Policy Check: Empty files (0 bytes) are rejected
    if total_size == 0:
        raise FileValidationError(
            code=ERROR_CODE_EMPTY_FILE,
            message="Uploaded file is empty (0 bytes).",
            http_status_code=400,
            details={"filename": sanitized_filename},
        )

    # Magic byte validation for binary formats
    header_snapshot = bytes(header_bytes)

    if extension == ".pdf":
        if not header_snapshot.startswith(PDF_MAGIC_BYTES):
            raise FileValidationError(
                code=ERROR_CODE_INVALID_MAGIC_BYTES,
                message="PDF file signature missing or invalid (expected %PDF- header).",
                http_status_code=400,
                details={
                    "extension": extension,
                    "expected_header": PDF_MAGIC_BYTES.hex(),
                    "actual_header": header_snapshot[:5].hex(),
                },
            )

    elif extension == ".png":
        if not header_snapshot.startswith(PNG_MAGIC_BYTES):
            raise FileValidationError(
                code=ERROR_CODE_INVALID_MAGIC_BYTES,
                message="PNG file signature missing or invalid (expected PNG magic bytes).",
                http_status_code=400,
                details={
                    "extension": extension,
                    "expected_header": PNG_MAGIC_BYTES.hex(),
                    "actual_header": header_snapshot[:8].hex(),
                },
            )

    storage_key = generate_storage_key(extension)

    return ValidationResult(
        original_filename=filename,
        sanitized_filename=sanitized_filename,
        extension=extension,
        media_type=media_type,
        size_bytes=total_size,
        sha256_checksum=sha256.hexdigest(),
        storage_key=storage_key,
    )


def validate_file_bytes(
    data: bytes,
    filename: str,
    content_type: str | None = None,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
) -> ValidationResult:
    """Convenience helper to validate in-memory bytes using the stream validator."""
    return validate_file_stream(
        stream=io.BytesIO(data),
        filename=filename,
        content_type=content_type,
        max_size_bytes=max_size_bytes,
    )


def validate_and_stage_upload(
    stream: IO[bytes],
    filename: str,
    target_storage_dir: Path | str,
    content_type: str | None = None,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
    chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> tuple[ValidationResult, Path]:
    """Validate and atomically stage an uploaded stream to private filesystem storage.

    Safety invariants:
    - Writes to an ephemeral .tmp file during stream validation.
    - Never uses original filename as destination path.
    - Cleans up temporary file immediately upon any validation failure or exception.
    - Renames temporary file to the randomized storage_key path only after full validation passes.

    Returns:
        (ValidationResult, staged_file_path)

    Raises:
        FileValidationError: If file fails validation.
    """
    sanitized_filename, extension = validate_filename(filename)
    media_type = validate_mime_type(content_type, extension)

    storage_path = Path(target_storage_dir)
    storage_path.mkdir(parents=True, exist_ok=True)

    # Ephemeral temporary file for atomic write & validation
    temp_id = f"upload_{uuid.uuid4().hex}.tmp"
    temp_file_path = storage_path / temp_id

    total_size = 0
    sha256 = hashlib.sha256()
    header_bytes = bytearray()
    header_needed = len(PNG_MAGIC_BYTES)

    txt_decoder = (
        codecs.getincrementaldecoder("utf-8")(errors="strict")
        if extension == ".txt"
        else None
    )

    try:
        with open(temp_file_path, "wb") as out_f:
            while True:
                chunk = stream.read(chunk_size_bytes)
                if not chunk:
                    break

                chunk_len = len(chunk)
                total_size += chunk_len

                if total_size > max_size_bytes:
                    raise FileValidationError(
                        code=ERROR_CODE_FILE_TOO_LARGE,
                        message=f"File exceeds maximum allowed size of {max_size_bytes} bytes (25 MiB).",
                        http_status_code=413,
                        details={"max_size_bytes": max_size_bytes, "exceeded_at_bytes": total_size},
                    )

                sha256.update(chunk)
                out_f.write(chunk)

                if len(header_bytes) < header_needed:
                    needed = header_needed - len(header_bytes)
                    header_bytes.extend(chunk[:needed])

                if txt_decoder is not None:
                    try:
                        txt_decoder.decode(chunk, final=False)
                    except UnicodeDecodeError as exc:
                        raise FileValidationError(
                            code=ERROR_CODE_INVALID_UTF8,
                            message="Text file contains malformed or non-UTF-8 byte sequences.",
                            http_status_code=400,
                            details={"error": str(exc)},
                        ) from exc

        if txt_decoder is not None:
            try:
                txt_decoder.decode(b"", final=True)
            except UnicodeDecodeError as exc:
                raise FileValidationError(
                    code=ERROR_CODE_INVALID_UTF8,
                    message="Text file contains incomplete or malformed UTF-8 byte sequence at end of file.",
                    http_status_code=400,
                    details={"error": str(exc)},
                ) from exc

        if total_size == 0:
            raise FileValidationError(
                code=ERROR_CODE_EMPTY_FILE,
                message="Uploaded file is empty (0 bytes).",
                http_status_code=400,
                details={"filename": sanitized_filename},
            )

        header_snapshot = bytes(header_bytes)
        if extension == ".pdf" and not header_snapshot.startswith(PDF_MAGIC_BYTES):
            raise FileValidationError(
                code=ERROR_CODE_INVALID_MAGIC_BYTES,
                message="PDF file signature missing or invalid (expected %PDF- header).",
                http_status_code=400,
                details={
                    "extension": extension,
                    "expected_header": PDF_MAGIC_BYTES.hex(),
                    "actual_header": header_snapshot[:5].hex(),
                },
            )

        if extension == ".png" and not header_snapshot.startswith(PNG_MAGIC_BYTES):
            raise FileValidationError(
                code=ERROR_CODE_INVALID_MAGIC_BYTES,
                message="PNG file signature missing or invalid (expected PNG magic bytes).",
                http_status_code=400,
                details={
                    "extension": extension,
                    "expected_header": PNG_MAGIC_BYTES.hex(),
                    "actual_header": header_snapshot[:8].hex(),
                },
            )

        storage_key = generate_storage_key(extension)
        final_file_path = storage_path / storage_key
        temp_file_path.replace(final_file_path)

        result = ValidationResult(
            original_filename=filename,
            sanitized_filename=sanitized_filename,
            extension=extension,
            media_type=media_type,
            size_bytes=total_size,
            sha256_checksum=sha256.hexdigest(),
            storage_key=storage_key,
        )
        return result, final_file_path

    except Exception:
        # Guarantee cleanup on failure
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except OSError:
                pass
        raise
