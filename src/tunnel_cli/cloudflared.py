import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel, ConfigDict, ValidationError

from .cloudflare import CloudflareTunnel
from .config import TunnelConfig
from .paths import cloudflared_config_path, cloudflared_credentials_path


class CloudflaredTunnel(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str

    def to_cloudflare_tunnel(self) -> CloudflareTunnel:
        return CloudflareTunnel(id=self.id, name=self.name)


class CloudflaredTunnelList(BaseModel):
    result: list[Any] | None = None
    tunnels: list[Any] | None = None

    @property
    def items(self) -> list[Any]:
        if self.result is not None:
            return self.result
        if self.tunnels is not None:
            return self.tunnels
        raise click.ClickException("cloudflared tunnel list returned unexpected JSON")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise click.ClickException(f"command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(f"{' '.join(command)} exited with {exc.returncode}") from exc


def run_command_output(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise click.ClickException(f"command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or f"{' '.join(command)} exited with {exc.returncode}"
        raise click.ClickException(message) from exc
    return completed.stdout


def run_json(args: list[str]) -> Any:
    output = run_command_output(["cloudflared", *args])
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char not in "[{":
            continue
        try:
            payload, _ = decoder.raw_decode(output[index:])
        except json.JSONDecodeError:
            continue
        return payload

    raise click.ClickException(f"cloudflared returned invalid JSON: {output.strip()}")


def tunnel_list(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return CloudflaredTunnelList.model_validate(raw).items
    raise click.ClickException(f"cloudflared tunnel list returned unexpected JSON: {raw!r}")


def parse_tunnel(raw: Any, context: str) -> CloudflareTunnel:
    try:
        return CloudflaredTunnel.model_validate(raw).to_cloudflare_tunnel()
    except ValidationError as exc:
        raise click.ClickException(f"{context} response was missing id/name: {exc}") from exc


def find_tunnel(tunnel_name: str) -> CloudflareTunnel | None:
    raw = run_json(["tunnel", "list", "--output", "json", "--name", tunnel_name])
    for item in tunnel_list(raw):
        try:
            tunnel = parse_tunnel(item, "cloudflared tunnel list")
        except click.ClickException:
            continue
        if tunnel.name == tunnel_name:
            return tunnel
    return None


def resolve_credentials(tunnel_id: str) -> str | None:
    for candidate in [cloudflared_credentials_path(), Path.home() / ".cloudflared" / f"{tunnel_id}.json"]:
        if candidate.exists():
            return str(candidate)
    return None


def create_tunnel(tunnel_name: str) -> tuple[CloudflareTunnel, str]:
    existing = find_tunnel(tunnel_name)
    if existing is not None:
        credentials = resolve_credentials(existing.id)
        if credentials is not None:
            click.echo(f"Using existing cloudflared tunnel {existing.name} ({existing.id})")
            return existing, credentials

        click.echo(
            f"Found existing cloudflared tunnel {existing.name} ({existing.id}), "
            "but no local credentials file."
        )
        if click.confirm("Delete and recreate this tunnel now?", default=True):
            run_command(["cloudflared", "tunnel", "delete", "-f", existing.name])
            click.echo(f"Deleted existing cloudflared tunnel {existing.name} ({existing.id}).")
        else:
            raise click.ClickException("choose a different tunnel name or recreate the tunnel with cloudflared")

    credentials_file = cloudflared_credentials_path()
    raw = run_json(
        [
            "tunnel",
            "create",
            "--output",
            "json",
            "--credentials-file",
            str(credentials_file),
            tunnel_name,
        ]
    )
    return parse_tunnel(raw, "cloudflared tunnel create"), str(credentials_file)


def ensure_login() -> None:
    if (Path.home() / ".cloudflared" / "cert.pem").exists():
        return

    click.echo("cloudflared needs a Cloudflare login certificate before it can create named tunnels.")
    if click.confirm("Run `cloudflared tunnel login` now?", default=True):
        run_command(["cloudflared", "tunnel", "login"])
        return

    raise click.ClickException("missing cloudflared login certificate; run `cloudflared tunnel login` first")


def write_config(config: TunnelConfig) -> None:
    path = cloudflared_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                f"tunnel: {config.tunnel_id}",
                f"credentials-file: {config.cloudflared_credentials}",
                "",
                "ingress:",
                f"  - hostname: {config.hostname}",
                f"    service: {config.service_url}",
                "  - service: http_status:404",
                "",
            ]
        )
    )
