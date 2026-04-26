import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import click

from .paths import config_path, credentials_path


@dataclass(frozen=True)
class TunnelConfig:
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
    service_port: int

    @property
    def service_url(self) -> str:
        return f"{self.service_scheme}://{self.service_host}:{self.service_port}"


@dataclass(frozen=True)
class Credentials:
    api_token: str
    account_id: str | None = None


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
    api_token = raw.get("api_token")
    if not isinstance(api_token, str) or not api_token.strip():
        raise click.ClickException(f"missing api_token in {credentials_path()}")
    account_id = raw.get("account_id")
    if account_id is None:
        return Credentials(api_token=api_token.strip())
    if not isinstance(account_id, str) or not account_id.strip():
        raise click.ClickException(f"account_id must be a non-empty string in {credentials_path()}")
    return Credentials(api_token=api_token.strip(), account_id=account_id.strip())


def load_credentials() -> Credentials | None:
    raw = read_json_file(credentials_path())
    if raw is None:
        return None
    return parse_credentials(raw)


def save_credentials(credentials: Credentials) -> None:
    payload: dict[str, Any] = {"api_token": credentials.api_token}
    if credentials.account_id:
        payload["account_id"] = credentials.account_id
    write_json_file(credentials_path(), payload, secret=True)


def parse_tunnel_config(raw: dict[str, Any]) -> TunnelConfig:
    try:
        service_port = int(raw["service_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise click.ClickException(f"invalid service_port in {config_path()}") from exc

    values: dict[str, str] = {}
    for key in [
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
    ]:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise click.ClickException(f"missing {key} in {config_path()}")
        values[key] = value.strip()

    return TunnelConfig(service_port=service_port, **values)


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
    write_json_file(config_path(), asdict(config))


def redact_token(token: str) -> str:
    if len(token) <= 8:
        return "********"
    return f"{token[:4]}...{token[-4:]}"
