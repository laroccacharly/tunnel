import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import click

from .cloudflare import CloudflareClient, CloudflareTunnel, Zone
from .config import (
    Credentials,
    TunnelConfig,
    load_credentials,
    load_tunnel_config,
    load_tunnel_config_values,
    redact_token,
    save_credentials,
    save_tunnel_config,
    save_tunnel_config_values,
)
from .paths import cloudflared_config_path, cloudflared_credentials_path, config_path, credentials_path


def require_config() -> TunnelConfig:
    config = load_tunnel_config()
    if config is None:
        raise click.ClickException(f"missing config; run `tunnel init` first ({config_path()})")
    return config


def require_credentials() -> Credentials:
    credentials = load_credentials()
    if credentials is None:
        raise click.ClickException(f"missing credentials; run `tunnel init` first ({credentials_path()})")
    return credentials


def choose_zone(zones: list[Zone], default_zone_id: str | None = None) -> Zone:
    if not zones:
        raise click.ClickException("no Cloudflare zones are visible to this token")
    if len(zones) == 1:
        zone = zones[0]
        click.echo(f"Using zone {zone.name} ({zone.account_name})")
        return zone

    choices = [f"{zone.name} ({zone.account_name})" for zone in zones]
    default_choice = None
    for zone, choice in zip(zones, choices, strict=True):
        if zone.id == default_zone_id:
            default_choice = choice
            break

    selected = click.prompt(
        "Zone",
        type=click.Choice(choices, case_sensitive=False),
        default=default_choice,
        show_choices=True,
    )
    return zones[choices.index(selected)]


def zones_for_account(zones: list[Zone], account_id: str) -> list[Zone]:
    account_zones = [zone for zone in zones if zone.account_id == account_id]
    if account_zones:
        return account_zones
    raise click.ClickException(f"no Cloudflare zones are visible for account {account_id}")


def normalize_suffix(suffix: str) -> str:
    value = suffix.strip().strip(".").lower()
    if not value:
        raise click.ClickException("hostname suffix cannot be empty")
    return value


def build_hostname(suffix: str, zone_name: str) -> str:
    normalized_suffix = normalize_suffix(suffix)
    if normalized_suffix == zone_name:
        return zone_name
    if normalized_suffix.endswith(f".{zone_name}"):
        return normalized_suffix
    return f"{normalized_suffix}.{zone_name}"


def string_config_default(values: dict[str, Any], key: str, fallback: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        return fallback
    return value.strip()


def port_config_default(values: dict[str, Any]) -> int | None:
    try:
        port = int(values["service_port"])
    except (TypeError, ValueError):
        return None
    except KeyError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def suffix_config_default(values: dict[str, Any], zone_name: str) -> str:
    hostname = string_config_default(values, "hostname", "")
    if not hostname:
        return "app"
    if hostname == zone_name:
        return zone_name
    if hostname.endswith(f".{zone_name}"):
        return hostname[: -(len(zone_name) + 1)]
    return hostname


def save_init_progress(values: dict[str, Any], **updates: Any) -> None:
    values.update(updates)
    save_tunnel_config_values(values)


def prompt_credentials(existing: Credentials | None) -> Credentials:
    if existing is not None and existing.account_id is not None:
        click.echo(
            f"Using Cloudflare API token from {credentials_path()} "
            f"({redact_token(existing.api_token)}) for account {existing.account_id}"
        )
        CloudflareClient(existing.api_token).verify_token(existing.account_id)
        return existing

    if existing is not None:
        click.echo(f"Using Cloudflare API token from {credentials_path()} ({redact_token(existing.api_token)})")
        token = existing.api_token
    else:
        token = click.prompt("Cloudflare API token", hide_input=True, confirmation_prompt=True).strip()

    account_id = click.prompt("Cloudflare account ID").strip()
    if not account_id:
        raise click.ClickException("Cloudflare account ID cannot be empty")

    credentials = Credentials(api_token=token, account_id=account_id)
    CloudflareClient(credentials.api_token).verify_token(credentials.account_id)
    save_credentials(credentials)
    click.echo(f"Wrote credentials: {credentials_path()}")
    return credentials


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: list[str], env_overrides: dict[str, str] | None = None) -> None:
    env = None
    if env_overrides is not None:
        env = dict(os.environ)
        env.update(env_overrides)
    try:
        subprocess.run(command, check=True, env=env)
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


def run_cloudflared_json(args: list[str]) -> Any:
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


def tunnel_from_cloudflared(raw: dict[str, Any]) -> CloudflareTunnel | None:
    tunnel_id = raw.get("id")
    name = raw.get("name")
    if not isinstance(tunnel_id, str) or not isinstance(name, str):
        return None
    return CloudflareTunnel(id=tunnel_id, name=name)


def cloudflared_tunnel_list(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        raise click.ClickException(f"cloudflared tunnel list returned unexpected JSON: {raw!r}")

    for key in ["result", "tunnels"]:
        value = raw.get(key)
        if isinstance(value, list):
            return value

    raise click.ClickException(f"cloudflared tunnel list returned unexpected JSON: {raw!r}")


def find_cloudflared_tunnel(tunnel_name: str) -> CloudflareTunnel | None:
    raw = run_cloudflared_json(["tunnel", "list", "--output", "json", "--name", tunnel_name])
    for item in cloudflared_tunnel_list(raw):
        if not isinstance(item, dict):
            continue
        tunnel = tunnel_from_cloudflared(item)
        if tunnel is not None and tunnel.name == tunnel_name:
            return tunnel
    return None


def resolve_cloudflared_credentials(tunnel_id: str) -> str:
    for candidate in [cloudflared_credentials_path(), Path.home() / ".cloudflared" / f"{tunnel_id}.json"]:
        if candidate.exists():
            return str(candidate)
    raise click.ClickException(
        f"found existing tunnel {tunnel_id}, but no local credentials file; "
        "choose a new tunnel name or recreate the tunnel with cloudflared"
    )


def create_cloudflared_tunnel(tunnel_name: str) -> tuple[CloudflareTunnel, str]:
    existing = find_cloudflared_tunnel(tunnel_name)
    if existing is not None:
        click.echo(f"Using existing cloudflared tunnel {existing.name} ({existing.id})")
        return existing, resolve_cloudflared_credentials(existing.id)

    credentials_file = cloudflared_credentials_path()
    raw = run_cloudflared_json(
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
    if not isinstance(raw, dict):
        raise click.ClickException("cloudflared tunnel create returned invalid JSON")

    tunnel = tunnel_from_cloudflared(raw)
    if tunnel is None:
        raise click.ClickException("cloudflared tunnel create response was missing id/name")
    return tunnel, str(credentials_file)


def ensure_cloudflared_login() -> None:
    cert_path = Path.home() / ".cloudflared" / "cert.pem"
    if cert_path.exists():
        return

    click.echo("cloudflared needs a Cloudflare login certificate before it can create named tunnels.")
    if click.confirm("Run `cloudflared tunnel login` now?", default=True):
        run_command(["cloudflared", "tunnel", "login"])
        return

    raise click.ClickException("missing cloudflared login certificate; run `cloudflared tunnel login` first")


def route_cloudflared_dns(tunnel: CloudflareTunnel, hostname: str) -> None:
    run_command(["cloudflared", "tunnel", "route", "dns", "--overwrite-dns", tunnel.id, hostname])


def write_cloudflared_config(config: TunnelConfig) -> None:
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


def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@click.group()
def cli() -> None:
    pass


@cli.command()
def init() -> None:
    if not command_exists("cloudflared"):
        raise click.ClickException("command not found: cloudflared")

    config_values = load_tunnel_config_values()
    credentials = prompt_credentials(load_credentials())
    client = CloudflareClient(credentials.api_token)

    if credentials.account_id is None:
        raise click.ClickException("missing account ID; run `tunnel init` again")

    zones = zones_for_account(client.list_zones(), credentials.account_id)
    default_zone_id = string_config_default(config_values, "zone_id", "")
    zone = choose_zone(zones, default_zone_id or None)
    save_init_progress(
        config_values,
        account_id=credentials.account_id,
        zone_id=zone.id,
        zone_name=zone.name,
    )

    tunnel_name_default = string_config_default(config_values, "tunnel_name", f"tunnel-{zone.name.replace('.', '-')}")
    tunnel_name = click.prompt("Tunnel name", default=tunnel_name_default).strip()
    save_init_progress(config_values, tunnel_name=tunnel_name)

    suffix = click.prompt("Hostname suffix/subdomain", default=suffix_config_default(config_values, zone.name)).strip()
    hostname = build_hostname(suffix, zone.name)
    save_init_progress(config_values, hostname=hostname)

    scheme_default = string_config_default(config_values, "service_scheme", "http")
    if scheme_default not in ["http", "https"]:
        scheme_default = "http"
    scheme = click.prompt("Local service scheme", default=scheme_default, type=click.Choice(["http", "https"]))
    save_init_progress(config_values, service_scheme=scheme)

    host = click.prompt("Local service host", default=string_config_default(config_values, "service_host", "localhost")).strip()
    save_init_progress(config_values, service_host=host)

    port_default = port_config_default(config_values)
    if port_default is None:
        port = click.prompt("Local service port", type=click.IntRange(min=1, max=65535))
    else:
        port = click.prompt("Local service port", default=port_default, type=click.IntRange(min=1, max=65535))
    save_init_progress(config_values, service_port=port)

    ensure_cloudflared_login()
    tunnel, tunnel_credentials = create_cloudflared_tunnel(tunnel_name)
    service_url = f"{scheme}://{host}:{port}"
    client.upsert_dns_cname(zone.id, hostname, tunnel.id)

    config = TunnelConfig(
        account_id=credentials.account_id,
        zone_id=zone.id,
        zone_name=zone.name,
        tunnel_id=tunnel.id,
        tunnel_name=tunnel.name,
        hostname=hostname,
        cloudflared_config=str(cloudflared_config_path()),
        cloudflared_credentials=tunnel_credentials,
        service_scheme=scheme,
        service_host=host,
        service_port=port,
    )
    save_credentials(Credentials(api_token=credentials.api_token, account_id=credentials.account_id))
    save_tunnel_config(config)
    write_cloudflared_config(config)

    click.echo(f"Wrote config: {config_path()}")
    click.echo(f"Wrote cloudflared config: {cloudflared_config_path()}")
    click.echo(f"Configured https://{hostname} -> {service_url}")


@cli.command(name="config")
def show_config() -> None:
    config = require_config()
    click.echo(json.dumps({**config.__dict__, "service_url": config.service_url}, indent=2, sort_keys=True))
    credentials = load_credentials()
    if credentials is not None:
        click.echo(f"credentials: {credentials_path()} ({redact_token(credentials.api_token)})")


@cli.command()
def run() -> None:
    config = require_config()
    run_command(["cloudflared", "tunnel", "--config", config.cloudflared_config, "run", config.tunnel_id])


@cli.command()
def status() -> None:
    config = require_config()
    click.echo(f"hostname: https://{config.hostname}")
    click.echo(f"service: {config.service_url}")
    click.echo(f"tunnel: {config.tunnel_name} ({config.tunnel_id})")
    run_command(["cloudflared", "tunnel", "info", config.tunnel_id])


@cli.command()
def doctor() -> None:
    config = require_config()
    checks: list[tuple[str, bool, str]] = []

    checks.append(("config-file", config_path().exists(), str(config_path())))
    checks.append(("credentials-file", credentials_path().exists(), str(credentials_path())))
    checks.append(("cloudflared-config", Path(config.cloudflared_config).exists(), config.cloudflared_config))
    checks.append(("cloudflared-credentials", Path(config.cloudflared_credentials).exists(), config.cloudflared_credentials))
    checks.append(
        (
            "local-service",
            check_tcp_port(config.service_host, config.service_port),
            config.service_url,
        )
    )

    try:
        run_command_output(["cloudflared", "tunnel", "info", config.tunnel_id])
        checks.append(("cloudflare-tunnel", True, config.tunnel_id))
    except click.ClickException as exc:
        checks.append(("cloudflare-tunnel", False, str(exc)))

    try:
        answers = socket.getaddrinfo(config.hostname, 443)
        checks.append(("public-dns", bool(answers), config.hostname))
    except OSError as exc:
        checks.append(("public-dns", False, str(exc)))

    failed = False
    for name, ok, detail in checks:
        if not ok:
            failed = True
        click.echo(f"{'[OK]' if ok else '[FAIL]'} {name}: {detail}")
    if failed:
        raise click.ClickException("doctor checks failed")


if __name__ == "__main__":
    cli()
