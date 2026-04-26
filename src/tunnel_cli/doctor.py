import socket
from dataclasses import dataclass
from pathlib import Path

import click

from .cloudflared import run_command_output
from .config import TunnelConfig
from .paths import config_path, credentials_path


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    description: str


def check_tcp_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def cloudflare_tunnel_check(tunnel_id: str) -> Check:
    description = f"Cloudflare can find tunnel ID {tunnel_id}"
    try:
        run_command_output(["cloudflared", "tunnel", "info", tunnel_id])
        return Check("cloudflare-tunnel", True, tunnel_id, description)
    except click.ClickException as exc:
        return Check("cloudflare-tunnel", False, str(exc), description)


def public_dns_check(hostname: str) -> Check:
    description = f"{hostname} resolves for HTTPS/TCP"
    try:
        addresses = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError as exc:
        return Check("public-dns", False, str(exc), description)
    resolved = sorted({item[4][0] for item in addresses})
    detail = ", ".join(resolved) if resolved else "no addresses returned"
    return Check("public-dns", bool(resolved), detail, description)


def checks_for(config: TunnelConfig) -> list[Check]:
    return [
        Check("config-file", config_path().exists(), str(config_path()), "local tunnel config file exists"),
        Check(
            "credentials-file",
            credentials_path().exists(),
            str(credentials_path()),
            "Cloudflare API token file exists",
        ),
        Check(
            "cloudflared-config",
            Path(config.cloudflared_config).exists(),
            config.cloudflared_config,
            "cloudflared YAML config file exists",
        ),
        Check(
            "cloudflared-credentials",
            Path(config.cloudflared_credentials).exists(),
            config.cloudflared_credentials,
            "named tunnel credentials file exists",
        ),
        Check(
            "local-service",
            check_tcp_port(config.service_host, config.service_port),
            config.service_url,
            f"local service accepts TCP connections at {config.service_host}:{config.service_port}",
        ),
        cloudflare_tunnel_check(config.tunnel_id),
        public_dns_check(config.hostname),
    ]
