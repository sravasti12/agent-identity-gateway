from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8-sig", extra="ignore")

    keycloak_issuer: str
    keycloak_client_id: str = Field(min_length=1)
    keycloak_client_secret: SecretStr
    keycloak_redirect_uri: str
    keycloak_api_audience: str = Field(min_length=1)

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
