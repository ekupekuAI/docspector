from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DocumentVersionResponse(BaseModel):
    """Pydantic response schema for a document version.

    Exposes version metadata and verified cryptographic hash without leaking
    internal server storage keys or absolute paths.
    """

    id: int
    document_id: int
    version_number: int
    state: str
    original_filename: str
    mime_type: str
    size_bytes: int
    sha256_hash: str
    created_by_user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DocumentResponse(BaseModel):
    """Pydantic response schema for a logical document."""

    id: int
    case_id: int
    document_number: str
    title: str
    created_by_user_id: int
    created_at: datetime
    current_version: DocumentVersionResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class DocumentRegistrationResponse(BaseModel):
    """Pydantic response schema for successful document registration (V1)."""

    document: DocumentResponse
    version: DocumentVersionResponse

    model_config = ConfigDict(from_attributes=True)
