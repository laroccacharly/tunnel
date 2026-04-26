import json
import os
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .paths import config_path, credentials_path


class TunnelConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    account_id: str
    zone_id: str
    zone_name: str
    tunnel_id: str
    tunnel_name: str
    hostname: str
    cloudflared_config: str
    cloudflared_credentials: str
    service_scheme: str
    service_host: str
    service_port: int = Field(ge=1, le=65535)

    @field_validator(
        "account_id",
        "zone_id",
        "zone_name",
        "tunnel_id",
        "tunnel_name",
        "hostname",
        "cloudflared_config",
        "cloudflared_credentials",
        "service_scheme",
        "service_host",
        mode="before",
    )
    @classmethod
    def strip_required_string(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("must be a non-empty string")
        return value.strip()

    @property
    def service_url(self) -> str:
        return f"{self.service_scheme}://{self.service_host}:{self.service_port}"


class Credentials(BaseModel):
    model_config = ConfigDict(frozen=True)

    api_token: str
    account_id: str | None = None

    @field_validator("api_token", mode="before")
    @classmethod
    def strip_api_token(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("must be a non-empty string")
        return value.strip()

    @field_validator("account_id", mode="before")
    @classmethod
    def strip_account_id(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError("must be a non-empty string")
        return value.strip()


def read_json_file(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if not path.is_file():
        raise click.ClickException(f"not a file: {path}")
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise click.ClickException(f"expected JSON object in {path}")
    return raw


def write_json_file(path: Path, payload: dict[str, Any], secret: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if secret:
        os.chmod(path, 0o600)


def parse_credentials(raw: dict[str, Any]) -> Credentials:
    try:
        return Credentials.model_validate(raw)
    except ValidationError as exc:
        raise click.ClickException(f"invalid credentials in {credentials_path()}: {exc}") from exc


def load_credentials() -> Credentials | None:
    raw = read_json_file(credentials_path())
    if raw is None:
        return None
    return parse_credentials(raw)


def save_credentials(credentials: Credentials) -> None:
    write_json_file(credentials_path(), credentials.model_dump(exclude_none=True), secret=True)


def parse_tunnel_config(raw: dict[str, Any]) -> TunnelConfig:
    try:
        return TunnelConfig.model_validate(raw)
    except ValidationError as exc:
        raise click.ClickException(f"invalid config in {config_path()}: {exc}") from exc


def load_tunnel_config() -> TunnelConfig | None:
    raw = read_json_file(config_path())
    if raw is None:
        return None
    return parse_tunnel_config(raw)


def load_tunnel_config_values() -> dict[str, Any]:
    raw = read_json_file(config_path())
    if raw is None:
        return {}
    return raw


def save_tunnel_config_values(values: dict[str, Any]) -> None:
    write_json_file(config_path(), values)


def save_tunnel_config(config: TunnelConfig) -> None:
    write_json_file(config_path(), config.model_dump())


def redact_token(token: str) -> str:
    if len(token) <= 8:
        return "********"
    return f"{token[:4]}...{token[-4:]}"
