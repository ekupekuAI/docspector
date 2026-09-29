from pydantic import BaseModel, ConfigDict


class DemoTamperResponse(BaseModel):
    """Structured response confirming simulated synthetic storage tampering."""

    simulation_type: str
    demo_mode: bool
    document_id: int
    document_version_id: int
    version_number: int
    persisted_expected_sha256: str
    message: str
    disclaimer: str = (
        "DEMO MODE ONLY: Simulated storage tampering performed on synthetic test data. "
        "Does not represent real forensic compromise."
    )

    model_config = ConfigDict(from_attributes=True)
