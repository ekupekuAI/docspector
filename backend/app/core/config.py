from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_SECRETS: frozenset[str] = frozenset({
    "docspector-development-only-secret-change-me",
    "docspector-super-secret-key-change-in-production-2026",
    "secret",
    "changeme",
    "password",
    "admin",
    "test",
    "dev",
    "12345678",
})

ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})


class Settings(BaseSettings):
    app_name: str = Field(default="Docspector")
    app_version: str = Field(default="0.1.0")
    app_env: str = Field(default="development")
    api_v1_prefix: str = Field(default="/api/v1")
    database_url: str = Field(default="sqlite:///./docspector.db")

    jwt_secret_key: str = Field(default="docspector-development-only-secret-change-me")
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=60)
    storage_dir: str = Field(default="./storage/private")
    demo_mode: bool = Field(default=False)
    # CORS Configuration
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
        ]
    )
    cors_allow_credentials: bool = Field(default=True)
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["*"])

    # Request Body Size Limits (Non-multipart / JSON API requests)
    max_json_body_size_bytes: int = Field(default=1 * 1024 * 1024)  # 1 MiB

    # In-Process Rate Limiting Configuration
    login_rate_limit_max_attempts: int = Field(default=5)
    login_rate_limit_window_seconds: int = Field(default=60)
    rate_limiter_max_keys: int = Field(default=10000)

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_cors_allowed_origins(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_security_invariants(self) -> "Settings":
        # 1. JWT Algorithm validation (prevent 'none' algorithm or weak asymmetric confusions)
        if self.jwt_algorithm.upper() not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"Unsupported JWT algorithm '{self.jwt_algorithm}'. Allowed algorithms: {sorted(ALLOWED_JWT_ALGORITHMS)}"
            )

        # 2. Token expiration sanity
        if self.jwt_access_token_expire_minutes <= 0:
            raise ValueError("jwt_access_token_expire_minutes must be a positive integer.")

        # 3. Production environment security assertions
        env_clean = self.app_env.lower().strip()
        is_production = env_clean in {"production", "prod"}

        if is_production:
            secret = (self.jwt_secret_key or "").strip()
            # Reject missing, empty, known default, or short (< 32 chars) JWT secret key in production
            if (
                not secret
                or secret in INSECURE_DEV_SECRETS
                or secret.startswith("docspector-development-")
                or secret.startswith("docspector-super-secret-")
                or len(secret) < 32
            ):
                raise ValueError(
                    "Insecure default or short JWT secret key (fewer than 32 characters or default string) is strictly prohibited in production environment."
                )

            # Prevent demo mode from being active in production
            if self.demo_mode:
                raise ValueError(
                    "DEMO_MODE is strictly forbidden in production environment."
                )

            # Reject wildcard '*' or empty CORS allowed origins in production
            parsed_origins = [o.strip() for o in self.cors_allowed_origins if o.strip()]
            if not parsed_origins or "*" in parsed_origins or any(o == "*" for o in parsed_origins):
                raise ValueError(
                    "Wildcard CORS origin '*' is strictly prohibited in production environment. Explicit origins must be configured."
                )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
