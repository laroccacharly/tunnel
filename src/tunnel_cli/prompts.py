from typing import Any

import click

from .cloudflare import CloudflareClient, Zone
from .config import Credentials, load_credentials, redact_token, save_credentials, save_tunnel_config_values
from .paths import credentials_path


def choose_zone(zones: list[Zone], default_zone_id: str | None = None) -> Zone:
    if not zones:
        raise click.ClickException("no Cloudflare zones are visible to this token")
    if len(zones) == 1:
        zone = zones[0]
        click.echo(f"Using zone {zone.name} ({zone.account_name})")
        return zone

    choices = [f"{zone.name} ({zone.account_name})" for zone in zones]
    default_choice = next((choice for zone, choice in zip(zones, choices, strict=True) if zone.id == default_zone_id), None)
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
    if normalized_suffix == zone_name or normalized_suffix.endswith(f".{zone_name}"):
        return normalized_suffix
    return f"{normalized_suffix}.{zone_name}"


def string_config_default(values: dict[str, Any], key: str, fallback: str) -> str:
    value = values.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def port_config_default(values: dict[str, Any]) -> int | None:
    try:
        port = int(values["service_port"])
    except (KeyError, TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


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


def prompt_saved_string(values: dict[str, Any], key: str, text: str, fallback: str) -> str:
    value = click.prompt(text, default=string_config_default(values, key, fallback)).strip()
    save_init_progress(values, **{key: value})
    return value


def prompt_credentials() -> Credentials:
    existing = load_credentials()
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
