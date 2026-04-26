import json
import subprocess
from pathlib import Path

import click

from . import cloudflared
from .cloudflare import CloudflareClient
from .config import (
    Credentials,
    TunnelConfig,
    clear_incomplete_tunnel_config,
    load_credentials,
    load_tunnel_config,
    load_tunnel_config_values,
    redact_token,
    save_credentials,
    save_tunnel_config,
)
from .doctor import checks_for
from .paths import cloudflared_config_path, config_path, credentials_path, log_path, state_path
from .process import clear_state, load_state, start_tunnel_process, state_process_is_running, stop_tunnel_process
from .prompts import (
    build_hostname,
    choose_zone,
    port_config_default,
    prompt_credentials,
    prompt_saved_string,
    save_init_progress,
    string_config_default,
    suffix_config_default,
    zones_for_account,
)


STALE_TUNNEL_MARKERS = (
    "tunnel not found",
    "found 0 tunnels",
    "unauthorized: tunnel not found",
)


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


def is_missing_cloudflare_tunnel_error(message: str) -> bool:
    normalized = message.lower()
    return any(marker in normalized for marker in STALE_TUNNEL_MARKERS)


def cloudflare_tunnel_exists(config: TunnelConfig) -> tuple[bool, str]:
    try:
        cloudflared.run_command_output(["cloudflared", "tunnel", "info", config.tunnel_id])
        return True, config.tunnel_id
    except click.ClickException as exc:
        return False, str(exc)


def recreate_configured_tunnel(config: TunnelConfig) -> TunnelConfig:
    credentials = require_credentials()
    client = CloudflareClient(credentials.api_token)

    removed = cloudflared.remove_credentials_file(config.cloudflared_credentials)
    if removed:
        click.echo(f"Removed stale tunnel credentials: {config.cloudflared_credentials}")

    tunnel, tunnel_credentials = cloudflared.create_tunnel(config.tunnel_name)
    client.upsert_dns_cname(config.zone_id, config.hostname, tunnel.id)

    repaired = config.model_copy(
        update={
            "tunnel_id": tunnel.id,
            "tunnel_name": tunnel.name,
            "cloudflared_credentials": tunnel_credentials,
        }
    )
    save_tunnel_config(repaired)
    cloudflared.write_config(repaired)
    click.echo(f"Recreated tunnel {repaired.tunnel_name} ({repaired.tunnel_id}).")
    click.echo(f"Updated DNS: https://{repaired.hostname} -> {repaired.service_url}")
    return repaired


def prompt_missing_tunnel_recovery(config: TunnelConfig, detail: str) -> TunnelConfig | None:
    click.echo(f"Configured tunnel {config.tunnel_name} ({config.tunnel_id}) was not found by Cloudflare.")
    click.echo(f"Detail: {detail}")
    choice = click.prompt(
        "Choose recovery action",
        type=click.Choice(["recreate", "init", "skip"], case_sensitive=False),
        default="recreate",
        show_choices=True,
    ).lower()
    if choice == "recreate":
        return recreate_configured_tunnel(config)
    if choice == "init":
        click.echo("Run `tunnel init` to choose values interactively.")
        return None

    click.echo("Leaving existing config unchanged.")
    return None


def ensure_configured_tunnel_available(config: TunnelConfig, *, prompt: bool) -> TunnelConfig:
    exists, detail = cloudflare_tunnel_exists(config)
    if exists:
        return config
    if prompt and is_missing_cloudflare_tunnel_error(detail):
        repaired = prompt_missing_tunnel_recovery(config, detail)
        if repaired is not None:
            return repaired
    raise click.ClickException(detail)


@click.group(help="Set up and run a Cloudflare Tunnel for a local service.")
def cli() -> None:
    pass


@cli.command(help="Interactively create tunnel config, DNS, and local cloudflared files.")
def init() -> None:
    config_values = load_tunnel_config_values()
    try:
        if not cloudflared.command_exists("cloudflared"):
            raise click.ClickException("command not found: cloudflared")

        credentials = prompt_credentials()
        client = CloudflareClient(credentials.api_token)

        if credentials.account_id is None:
            raise click.ClickException("missing account ID; run `tunnel init` again")

        zones = zones_for_account(client.list_zones(), credentials.account_id)
        zone = choose_zone(zones, string_config_default(config_values, "zone_id", "") or None)
        save_init_progress(config_values, account_id=credentials.account_id, zone_id=zone.id, zone_name=zone.name)

        tunnel_name = prompt_saved_string(
            config_values,
            "tunnel_name",
            "Tunnel name",
            f"tunnel-{zone.name.replace('.', '-')}",
        )
        suffix = click.prompt("Hostname suffix/subdomain", default=suffix_config_default(config_values, zone.name)).strip()
        hostname = build_hostname(suffix, zone.name)
        save_init_progress(config_values, hostname=hostname)

        scheme_default = string_config_default(config_values, "service_scheme", "http")
        scheme_default = scheme_default if scheme_default in ["http", "https"] else "http"
        scheme = click.prompt("Local service scheme", default=scheme_default, type=click.Choice(["http", "https"]))
        save_init_progress(config_values, service_scheme=scheme)

        host = prompt_saved_string(config_values, "service_host", "Local service host", "localhost")
        port_kwargs = {"type": click.IntRange(min=1, max=65535)}
        port_default = port_config_default(config_values)
        if port_default is not None:
            port_kwargs["default"] = port_default
        port = click.prompt("Local service port", **port_kwargs)
        save_init_progress(config_values, service_port=port)

        cloudflared.ensure_login()
        tunnel, tunnel_credentials = cloudflared.create_tunnel(tunnel_name)
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
        cloudflared.write_config(config)
    except click.ClickException:
        if clear_incomplete_tunnel_config():
            click.echo(f"Removed incomplete config: {config_path()}")
        raise

    click.echo(f"Wrote config: {config_path()}")
    click.echo(f"Wrote cloudflared config: {cloudflared_config_path()}")
    click.echo(f"Configured https://{hostname} -> {config.service_url}")
    click.echo("Run `tunnel run` to start the tunnel.")


@cli.command(name="config", help="Print the saved tunnel configuration and credentials location.")
def show_config() -> None:
    config = require_config()
    click.echo(json.dumps({**config.model_dump(), "service_url": config.service_url}, indent=2, sort_keys=True))
    credentials = load_credentials()
    if credentials is not None:
        click.echo(f"credentials: {credentials_path()} ({redact_token(credentials.api_token)})")


@cli.command(help="Start cloudflared in the background and write process state under ~/.tunnel.")
def run() -> None:
    config = ensure_configured_tunnel_available(require_config(), prompt=True)
    existing = load_state()
    if existing is not None:
        if state_process_is_running(existing):
            click.echo(f"Tunnel is already running in the background (pid {existing.pid}).")
            click.echo(f"Logs: {existing.log_file}")
            return
        clear_state()

    command = ["cloudflared", "tunnel", "--config", config.cloudflared_config, "run", config.tunnel_id]
    state = start_tunnel_process(command, config.tunnel_id)
    click.echo(f"Started tunnel in the background (pid {state.pid}).")
    click.echo(f"Logs: {state.log_file}")
    click.echo("Run `tunnel log` to follow logs, or `tunnel stop` to stop it.")


@cli.command(name="log", help="Tail the background tunnel log file.")
@click.option("--lines", "-n", default=100, show_default=True, type=click.IntRange(min=0), help="Initial lines to show.")
def show_log(lines: int) -> None:
    state = load_state()
    path = Path(state.log_file) if state is not None else log_path()
    if not path.exists():
        raise click.ClickException(f"missing log file: {path}")

    try:
        subprocess.run(["tail", "-n", str(lines), "-f", str(path)], check=True)
    except FileNotFoundError as exc:
        raise click.ClickException("command not found: tail") from exc
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(f"tail exited with {exc.returncode}") from exc


@cli.command(help="Stop the background tunnel process recorded in ~/.tunnel/state.json.")
def stop() -> None:
    state = load_state()
    if state is None:
        click.echo(f"Tunnel is not running; no process state found at {state_path()}.")
        return

    stopped = stop_tunnel_process(state)
    if stopped:
        click.echo(f"Stopped tunnel process {state.pid}.")
    else:
        click.echo(f"Tunnel process {state.pid} was not running; removed stale state.")


@cli.command(help="Show tunnel endpoints, process state, and cloudflared tunnel info.")
def status() -> None:
    config = require_config()
    click.echo(f"hostname: https://{config.hostname}")
    click.echo(f"service: {config.service_url}")
    click.echo(f"tunnel: {config.tunnel_name} ({config.tunnel_id})")
    state = load_state()
    if state is None:
        click.echo("process: not running")
    elif state_process_is_running(state):
        click.echo(f"process: running (pid {state.pid})")
        click.echo(f"logs: {state.log_file}")
    else:
        clear_state()
        click.echo(f"process: not running (removed stale state for pid {state.pid})")
    config = ensure_configured_tunnel_available(config, prompt=click.get_text_stream("stdin").isatty())
    cloudflared.run_command(["cloudflared", "tunnel", "info", config.tunnel_id])


@cli.command(help="Run local checks for config, dependencies, DNS, and service reachability.")
def doctor() -> None:
    config = require_config()
    checks = checks_for(config)
    tunnel_check = next((check for check in checks if check.name == "cloudflare-tunnel"), None)
    if (
        tunnel_check is not None
        and not tunnel_check.ok
        and click.get_text_stream("stdin").isatty()
        and is_missing_cloudflare_tunnel_error(tunnel_check.detail)
    ):
        repaired = prompt_missing_tunnel_recovery(config, tunnel_check.detail)
        if repaired is not None:
            checks = checks_for(repaired)

    for check in checks:
        click.echo(f"{'[OK]' if check.ok else '[FAIL]'} {check.name}: {check.description}; result: {check.detail}")
    if any(not check.ok for check in checks):
        raise click.ClickException("doctor checks failed")


@cli.command(name="delete", help="Delete the Cloudflare tunnel, DNS record, and local tunnel config.")
@click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation.")
def delete_tunnel(yes: bool) -> None:
    if not cloudflared.command_exists("cloudflared"):
        raise click.ClickException("command not found: cloudflared")

    config = require_config()
    credentials = require_credentials()
    if not yes:
        click.confirm(
            f"This will remove the CNAME for {config.hostname!r} via the API (if present), run "
            f"`cloudflared tunnel delete` for {config.tunnel_name!r} ({config.tunnel_id}), and remove local config under "
            f"{config_path().parent}. Your API token file is kept. Continue?",
            abort=True,
        )

    removed_dns = CloudflareClient(credentials.api_token).delete_dns_cname_to_tunnel(
        config.zone_id,
        config.hostname,
        config.tunnel_id,
    )
    if removed_dns:
        click.echo(f"Removed {removed_dns} DNS CNAME record(s) for {config.hostname} (API).")
    else:
        click.echo(f"No CNAME for {config.hostname} pointing at this tunnel (API; skipped or already removed).")

    cloudflared.run_command(["cloudflared", "tunnel", "delete", "-f", config.tunnel_name])
    click.echo(f"Deleted Cloudflare tunnel {config.tunnel_name} (via cloudflared).")

    for path_str, label in (
        (config.cloudflared_config, "cloudflared config"),
        (config.cloudflared_credentials, "tunnel credentials"),
        (str(config_path()), "tunnel config"),
    ):
        path = Path(path_str)
        if path.is_file():
            path.unlink()
            click.echo(f"Removed {label}: {path}")

    click.echo("Done. Run `tunnel init` to set up a new tunnel.")


if __name__ == "__main__":
    cli()
