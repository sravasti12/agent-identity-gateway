from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8-sig", extra="ignore")

    keycloak_issuer: str
    keycloak_client_id: str = Field(min_length=1)
    keycloak_client_secret: SecretStr
    keycloak_redirect_uri: str
    keycloak_api_audience: str = Field(min_length=1)
    keycloak_hr_agent_client_id: str | None = None
    keycloak_hr_agent_client_secret: SecretStr | None = None
    delegation_enabled: bool = False
    opa_url: str = "http://127.0.0.1:8181"
    gateway_database: str = Field(default="gateway-state.sqlite3", min_length=1)
    access_review_days: int = Field(default=30, ge=1, le=3650)

    @field_validator("opa_url")
    @classmethod
    def validate_opa_url(cls, value: str) -> str:
        value = cls.validate_url(value)
        if urlsplit(value).path not in ("", "/"):
            raise ValueError("OPA URL must be a base URL without a path")
        return value.rstrip("/")

    @field_validator("keycloak_hr_agent_client_id")
    @classmethod
    def validate_agent_id(cls, value: str | None) -> str | None:
        if value is not None and (not value or value != value.strip()):
            raise ValueError("Expected a non-empty agent client ID without surrounding whitespace")
        return value

    @model_validator(mode="after")
    def validate_agent_credentials(self) -> "Settings":
        client_id = self.keycloak_hr_agent_client_id
        secret = self.keycloak_hr_agent_client_secret
        if client_id is None and secret is None:
            if self.delegation_enabled:
                raise ValueError("Delegation requires HR agent credentials")
            return self
        if client_id is None or secret is None or not secret.get_secret_value().strip():
            raise ValueError("Configure both HR agent client ID and secret")
        if client_id == self.keycloak_client_id:
            raise ValueError("The HR agent requires a separate Keycloak client")
        if self.delegation_enabled and not client_id.isascii():
            raise ValueError("Delegation requires an ASCII agent client ID")
        if self.delegation_enabled and any(char.isspace() or char == ":" for char in client_id):
            raise ValueError("Delegation requires an unambiguous client ID scope parameter")
        return self

    @field_validator("keycloak_client_secret")
    @classmethod
    def require_secret(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("Keycloak client secret is required")
        return value

    @field_validator("keycloak_issuer", "keycloak_redirect_uri")
    @classmethod
    def validate_url(cls, value: str) -> str:
        url = urlsplit(value)
        loopback = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            not url.hostname
            or url.username is not None
            or url.query
            or url.fragment
            or (url.scheme != "https" and not (url.scheme == "http" and loopback))
        ):
            raise ValueError("Use HTTPS or loopback HTTP without credentials, query or fragment")
        return value

    @property
    def secure_cookies(self) -> bool:
        return self.keycloak_redirect_uri.startswith("https://")
