from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    username: str

    model_config = ConfigDict(extra="forbid")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserIdentity(BaseModel):
    id: int
    username: str
    display_name: str
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)
